using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace WebAppNetCore.OAuth
{
    /// <summary>
    /// Calls the UserInfo endpoint of the discovery document. The sample calls UserInfo itself instead of the handler,
    /// because the handler always uses the Bearer scheme.
    /// </summary>
    public sealed class UserInfoClient
    {
        private const string Step = "UserInfo request";

        private readonly IHttpClientFactory httpClientFactory;
        private readonly IdentifyMetadata identifyMetadata;
        private readonly IConfiguration configuration;
        private readonly DPoPNonceStore dpopNonces;

        public UserInfoClient(IHttpClientFactory httpClientFactory, IdentifyMetadata identifyMetadata, IConfiguration configuration, DPoPNonceStore dpopNonces)
        {
            this.httpClientFactory = httpClientFactory;
            this.identifyMetadata = identifyMetadata;
            this.configuration = configuration;
            this.dpopNonces = dpopNonces;
        }

        /// <summary>
        /// Calls UserInfo with the scheme of the token type: DPoP with a proof for a DPoP-bound access token (RFC 9449 section 7),
        /// and Bearer otherwise. Returns null when the discovery document has no UserInfo endpoint or when there is no access token,
        /// as the handler does.
        /// </summary>
        public async Task<UserInfoResponse> GetAsync(string accessToken, string tokenType, ClientSession session, Fault fault, CancellationToken cancellationToken)
        {
            var metadata = await identifyMetadata.GetAsync(cancellationToken);
            var userInfoEndpoint = metadata.UserInfoEndpoint;
            if (string.IsNullOrEmpty(userInfoEndpoint) || string.IsNullOrEmpty(accessToken))
            {
                return null;
            }

            DPoPKey dpopKey = null;
            if (string.Equals(tokenType, "DPoP", StringComparison.OrdinalIgnoreCase) && fault != Fault.BearerAtUserInfo)
            {
                dpopKey = session?.DPoPKey ?? throw new OAuthClientException(
                    "The access token is bound to a DPoP key, but the key of this sign-in is no longer available, for example after a restart. Sign in again.");
            }

            // UserInfoProofOtherKey signs a valid proof with a new key: the use of the access token by another key holder.
            using var otherKey = dpopKey != null && fault == Fault.UserInfoProofOtherKey ? DPoPKey.Create() : null;
            var server = DPoPNonceStore.ResourceServer(userInfoEndpoint);
            string replayedProof = null;
            for (var attempt = 1; ; attempt++)
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, userInfoEndpoint);
                string proof = null;
                if (dpopKey != null)
                {
                    proof = replayedProof ?? CreateProof(fault, otherKey ?? dpopKey, userInfoEndpoint, metadata.TokenEndpoint, accessToken, dpopNonces.Get(server));
                    request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", accessToken);
                    request.Headers.Add("DPoP", proof);
                }
                else
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                }

                using var response = await httpClientFactory.CreateClient(IdentifyHttpClient.Name).SendAsync(request, cancellationToken);
                dpopNonces.Save(server, response);
                if (fault == Fault.ReplayDPoPProof && proof != null && replayedProof == null)
                {
                    session?.Trace.AddExchange(Step, request, null, null, (int)response.StatusCode, "fault ReplayDPoPProof: the next call sends the same proof");
                    replayedProof = proof;
                    continue;
                }

                if (!response.IsSuccessStatusCode)
                {
                    var challengedNonce = dpopKey != null && attempt == 1 ? await DPoPNonce.ReadChallengeAsync(response) : null;
                    if (challengedNonce != null)
                    {
                        session?.Trace.AddExchange(Step, request, null, null, (int)response.StatusCode, "use_dpop_nonce: retry with the server nonce");
                        continue;
                    }

                    var error = await OAuthErrorResponseException.CreateAsync("UserInfo endpoint", response);
                    session?.Trace.AddExchange(Step, request, null, null, error.StatusCode, error.Error + " " + error.ErrorDescription);
                    throw error;
                }

                var userInfo = await ReadResponseAsync(response, cancellationToken);
                session?.Trace.AddExchange(Step, request, null, null, (int)response.StatusCode, response.Content.Headers.ContentType?.MediaType);
                return userInfo;
            }
        }

        /// <summary>
        /// The UserInfo proof, changed by MissingAth, UserInfoProofWrongHtm, UserInfoProofWrongHtu, or UserInfoProofWrongAth.
        /// </summary>
        private string CreateProof(Fault fault, DPoPKey key, string userInfoEndpoint, string tokenEndpoint, string accessToken, string nonce)
        {
            var method = fault == Fault.UserInfoProofWrongHtm ? "POST" : "GET";
            var htu = fault == Fault.UserInfoProofWrongHtu ? IdentifyMetadata.RequireEndpoint(tokenEndpoint, "token_endpoint") : userInfoEndpoint;
            var athToken = fault switch
            {
                Fault.MissingAth => null,
                Fault.UserInfoProofWrongAth => accessToken + "-other",
                _ => accessToken
            };
            return DPoPProofFactory.Create(key, configuration.DPoPSigningAlgorithm(), method, htu, athToken, nonce);
        }

        private static async Task<UserInfoResponse> ReadResponseAsync(HttpResponseMessage response, CancellationToken cancellationToken)
        {
            var rawResponse = await response.Content.ReadAsStringAsync(cancellationToken);
            var mediaType = response.Content.Headers.ContentType?.MediaType;
            if (string.Equals(mediaType, "application/json", StringComparison.OrdinalIgnoreCase))
            {
                return new UserInfoResponse(rawResponse, rawResponse);
            }

            if (string.Equals(mediaType, "application/jwt", StringComparison.OrdinalIgnoreCase))
            {
                // As the handler does, the sample reads the claims of a signed response without validating the signature.
                return new UserInfoResponse(rawResponse, Base64UrlEncoder.Decode(new JsonWebToken(rawResponse).EncodedPayload));
            }

            throw new OAuthClientException("The UserInfo endpoint returned the unknown content type '" + mediaType + "'.");
        }
    }

    public sealed class UserInfoResponse
    {
        public UserInfoResponse(string rawResponse, string json)
        {
            RawResponse = rawResponse;
            Json = json;
        }

        /// <summary>The response body: JSON, or a JWT for a signed response.</summary>
        public string RawResponse { get; }

        /// <summary>The claims as JSON.</summary>
        public string Json { get; }
    }
}
