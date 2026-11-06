using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
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

        private readonly IdentifyBackChannel backChannel;
        private readonly IdentifyMetadata identifyMetadata;
        private readonly IConfiguration configuration;
        private readonly DPoPNonceStore dpopNonces;

        public UserInfoClient(IdentifyBackChannel backChannel, IdentifyMetadata identifyMetadata, IConfiguration configuration, DPoPNonceStore dpopNonces)
        {
            this.backChannel = backChannel;
            this.identifyMetadata = identifyMetadata;
            this.configuration = configuration;
            this.dpopNonces = dpopNonces;
        }

        /// <summary>
        /// Calls UserInfo with the scheme of the token type: DPoP with a proof for a DPoP-bound access token (RFC 9449 section 7),
        /// and Bearer otherwise. With mutual TLS, the request goes to the UserInfo alias with the client certificate
        /// (IdentifyBackChannel.UserInfoEndpoint). Returns null when the discovery document has no UserInfo endpoint or when there is
        /// no access token, as the handler does.
        /// </summary>
        public async Task<UserInfoResponse> GetAsync(string accessToken, string tokenType, ClientSession session, Fault fault, CancellationToken cancellationToken)
        {
            var metadata = await identifyMetadata.GetAsync(cancellationToken);
            var target = backChannel.UserInfoEndpoint(metadata, fault);
            var userInfoEndpoint = target.Endpoint;
            if (string.IsNullOrEmpty(userInfoEndpoint) || string.IsNullOrEmpty(accessToken))
            {
                return null;
            }

            var boundToken = string.Equals(tokenType, "DPoP", StringComparison.OrdinalIgnoreCase);
            RequireTokenTypeOfFault(fault, boundToken);
            DPoPKey dpopKey = null;
            if (boundToken && fault != Fault.BearerAtUserInfo)
            {
                dpopKey = session?.DPoPKey ?? throw new OAuthClientException(
                    "The access token is bound to a DPoP key, but the key of this sign-in is no longer available, for example after a restart. Sign in again.");
            }

            // UserInfoProofOtherKey signs a valid proof with a new key: the use of the access token by another key holder.
            // DPoPSchemeForBearerToken sends a token without cnf.jkt with the DPoP scheme and a valid proof of a new key.
            using var newKey = (dpopKey != null && fault == Fault.UserInfoProofOtherKey) || fault == Fault.DPoPSchemeForBearerToken ? DPoPKey.Create() : null;
            var proofKey = newKey ?? dpopKey;
            var server = DPoPNonceStore.ResourceServer(userInfoEndpoint);
            string replayedProof = null;
            for (var attempt = 1; ; attempt++)
            {
                // AccessTokenInForm sends the token in the access_token parameter of a form POST (RFC 6750 section 2.2), and
                // AccessTokenInQuery in the access_token query parameter (RFC 6750 section 2.3), which FAPI 2.0 section 5.3.4 forbids.
                var form = fault == Fault.AccessTokenInForm ? new Dictionary<string, string> { ["access_token"] = accessToken } : null;
                var inQuery = fault == Fault.AccessTokenInQuery;
                var requestUri = inQuery ? QueryHelpers.AddQueryString(userInfoEndpoint, "access_token", accessToken) : userInfoEndpoint;
                using var request = new HttpRequestMessage(form == null ? HttpMethod.Get : HttpMethod.Post, requestUri);
                string proof = null;
                if (proofKey != null && fault != Fault.DPoPSchemeWithoutProof)
                {
                    proof = replayedProof ?? CreateProof(fault, proofKey, request.Method.Method, userInfoEndpoint, metadata.TokenEndpoint, accessToken, dpopNonces.Get(server));
                    request.Headers.Add("DPoP", proof);
                }

                if (form != null)
                {
                    request.Content = new FormUrlEncodedContent(form);
                }
                else if (!inQuery)
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue(proofKey != null ? "DPoP" : "Bearer", accessToken);
                }

                using var response = await backChannel.SendAsync(request, target.SendsCertificate, cancellationToken);
                dpopNonces.Save(server, response);
                if (fault == Fault.ReplayDPoPProof && proof != null && replayedProof == null)
                {
                    session?.Trace.AddExchange(Step, request, form, null, (int)response.StatusCode, "fault ReplayDPoPProof: the next call sends the same proof");
                    replayedProof = proof;
                    continue;
                }

                if (!response.IsSuccessStatusCode)
                {
                    var challengedNonce = proof != null && attempt == 1 ? await DPoPNonce.ReadChallengeAsync(response) : null;
                    if (challengedNonce != null)
                    {
                        session?.Trace.AddExchange(Step, request, form, null, (int)response.StatusCode, "use_dpop_nonce: retry with the server nonce");
                        continue;
                    }

                    var error = await OAuthErrorResponseException.CreateAsync("UserInfo endpoint", response);
                    session?.Trace.AddExchange(Step, request, form, null, error.StatusCode, error.Error + " " + error.ErrorDescription, ChallengeDetails(response));
                    throw error;
                }

                var userInfo = await ReadResponseAsync(response, cancellationToken);
                session?.Trace.AddExchange(Step, request, form, null, (int)response.StatusCode, response.Content.Headers.ContentType?.MediaType);
                return userInfo;
            }
        }

        private static readonly Fault[] BoundTokenFaults =
        {
            Fault.AccessTokenInForm, Fault.DPoPSchemeWithoutProof, Fault.AccessTokenInQuery,
            Fault.UserInfoProofAlgNone, Fault.UserInfoProofSignatureOtherKey, Fault.UserInfoProofWithoutJti, Fault.UserInfoProofIatOld
        };

        /// <summary>
        /// A fault that changes how a DPoP-bound token is sent needs such a token, and DPoPSchemeForBearerToken needs a token
        /// without the binding. Otherwise the request would be a valid one, and the result would look like an accepted violation.
        /// </summary>
        private static void RequireTokenTypeOfFault(Fault fault, bool boundToken)
        {
            if (BoundTokenFaults.Contains(fault) && !boundToken)
            {
                throw new OAuthClientException(
                    "The fault " + fault + " needs a DPoP-bound access token: sign in with DPoP:BindAccessTokens=true. The UserInfo request was not sent.");
            }

            if (fault == Fault.DPoPSchemeForBearerToken && boundToken)
            {
                throw new OAuthClientException(
                    "The fault DPoPSchemeForBearerToken needs an access token that is not bound to a DPoP key: sign in with DPoP:BindAccessTokens=false. The UserInfo request was not sent.");
            }
        }

        /// <summary>
        /// The WWW-Authenticate challenges of an error response, for the trace: RFC 9449 section 7.1 has the DPoP scheme and
        /// the algs parameter.
        /// </summary>
        private static IEnumerable<KeyValuePair<string, string>> ChallengeDetails(HttpResponseMessage response)
        {
            return response.Headers.WwwAuthenticate.Select(challenge => ProtocolTrace.Detail("WWW-Authenticate", challenge.ToString()));
        }

        /// <summary>
        /// The UserInfo proof for the HTTP method of the request, changed by MissingAth, UserInfoProofWrongHtm,
        /// UserInfoProofWrongHtu, or UserInfoProofWrongAth, or forged by a UserInfo fault with the same change as a token proof fault.
        /// </summary>
        private string CreateProof(Fault fault, DPoPKey key, string httpMethod, string userInfoEndpoint, string tokenEndpoint, string accessToken, string nonce)
        {
            var method = fault == Fault.UserInfoProofWrongHtm ? "POST" : httpMethod;
            var htu = fault == Fault.UserInfoProofWrongHtu ? IdentifyMetadata.RequireEndpoint(tokenEndpoint, "token_endpoint") : userInfoEndpoint;
            var athToken = fault switch
            {
                Fault.MissingAth => null,
                Fault.UserInfoProofWrongAth => accessToken + "-other",
                _ => accessToken
            };
            var proofFault = fault switch
            {
                Fault.UserInfoProofAlgNone => Fault.ProofAlgNone,
                Fault.UserInfoProofSignatureOtherKey => Fault.ProofSignatureOtherKey,
                Fault.UserInfoProofWithoutJti => Fault.ProofWithoutJti,
                Fault.UserInfoProofIatOld => Fault.ProofIatOld,
                _ => Fault.None
            };
            return DPoPProofFactory.Create(proofFault, key, configuration.DPoPSigningAlgorithm(), method, htu, athToken, nonce);
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
