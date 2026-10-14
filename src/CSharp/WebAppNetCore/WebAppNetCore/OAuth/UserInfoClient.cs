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
        private readonly IHttpClientFactory httpClientFactory;
        private readonly IdentifyMetadata identifyMetadata;
        private readonly IConfiguration configuration;

        public UserInfoClient(IHttpClientFactory httpClientFactory, IdentifyMetadata identifyMetadata, IConfiguration configuration)
        {
            this.httpClientFactory = httpClientFactory;
            this.identifyMetadata = identifyMetadata;
            this.configuration = configuration;
        }

        /// <summary>
        /// Calls UserInfo with the scheme of the token type: DPoP with a proof for a DPoP-bound access token (RFC 9449 section 7),
        /// and Bearer otherwise. Returns null when the discovery document has no UserInfo endpoint or when there is no access token,
        /// as the handler does.
        /// </summary>
        public async Task<UserInfoResponse> GetAsync(string accessToken, string tokenType, ClientSession session, CancellationToken cancellationToken)
        {
            var metadata = await identifyMetadata.GetAsync(cancellationToken);
            var userInfoEndpoint = metadata.UserInfoEndpoint;
            if (string.IsNullOrEmpty(userInfoEndpoint) || string.IsNullOrEmpty(accessToken))
            {
                return null;
            }

            DPoPKey dpopKey = null;
            if (string.Equals(tokenType, "DPoP", StringComparison.OrdinalIgnoreCase))
            {
                dpopKey = session?.DPoPKey ?? throw new OAuthClientException(
                    "The access token is bound to a DPoP key, but the key of this sign-in is no longer available, for example after a restart. Sign in again.");
            }

            string dpopNonce = null;
            for (var attempt = 1; ; attempt++)
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, userInfoEndpoint);
                if (dpopKey != null)
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", accessToken);
                    request.Headers.Add("DPoP", DPoPProofFactory.Create(dpopKey, configuration.DPoPSigningAlgorithm(), "GET", userInfoEndpoint, accessToken, dpopNonce));
                }
                else
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                }

                using var response = await httpClientFactory.CreateClient(IdentifyHttpClient.Name).SendAsync(request, cancellationToken);
                if (!response.IsSuccessStatusCode)
                {
                    var challengedNonce = dpopKey != null && attempt == 1 ? await DPoPNonce.ReadChallengeAsync(response) : null;
                    if (challengedNonce != null)
                    {
                        dpopNonce = challengedNonce;
                        continue;
                    }

                    throw await OAuthErrorResponseException.CreateAsync("UserInfo endpoint", response);
                }

                return await ReadResponseAsync(response, cancellationToken);
            }
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
