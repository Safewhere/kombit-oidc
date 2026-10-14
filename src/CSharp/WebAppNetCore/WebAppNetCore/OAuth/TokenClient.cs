using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace WebAppNetCore.OAuth
{
    /// <summary>
    /// Sends token requests to the token endpoint of the discovery document. With DPoP:BindAccessTokens, each request carries a
    /// DPoP proof of the key of the sign-in.
    /// </summary>
    public sealed class TokenClient
    {
        private readonly IHttpClientFactory httpClientFactory;
        private readonly IdentifyMetadata identifyMetadata;
        private readonly ClientAuthentication clientAuthentication;
        private readonly IConfiguration configuration;

        public TokenClient(IHttpClientFactory httpClientFactory, IdentifyMetadata identifyMetadata, ClientAuthentication clientAuthentication, IConfiguration configuration)
        {
            this.httpClientFactory = httpClientFactory;
            this.identifyMetadata = identifyMetadata;
            this.clientAuthentication = clientAuthentication;
            this.configuration = configuration;
        }

        public Task<OpenIdConnectMessage> RedeemCodeAsync(
            string code, string redirectUri, string codeVerifier, string sessionState, ClientSession session, CancellationToken cancellationToken)
        {
            var parameters = new Dictionary<string, string>
            {
                { "grant_type", "authorization_code" },
                { "code", code },
                { "redirect_uri", redirectUri },
                { "code_verifier", codeVerifier }
            };
            if (!string.IsNullOrEmpty(sessionState))
            {
                parameters["session_state"] = sessionState;
            }

            return SendAsync(parameters, session, cancellationToken);
        }

        private async Task<OpenIdConnectMessage> SendAsync(Dictionary<string, string> grantParameters, ClientSession session, CancellationToken cancellationToken)
        {
            var metadata = await identifyMetadata.GetAsync(cancellationToken);
            var tokenEndpoint = IdentifyMetadata.RequireEndpoint(metadata.TokenEndpoint, "token_endpoint");

            DPoPKey dpopKey = null;
            if (configuration.DPoPBindAccessTokens())
            {
                dpopKey = session?.DPoPKey ?? throw new OAuthClientException("The DPoP key of this sign-in is no longer available, for example after a restart. Sign in again.");
            }

            string dpopNonce = null;
            for (var attempt = 1; ; attempt++)
            {
                // Each attempt has a new client assertion and a new proof, because Identify rejects a replayed jti.
                var parameters = new Dictionary<string, string>(grantParameters);
                using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint);
                clientAuthentication.Apply(request, parameters, metadata);
                if (dpopKey != null)
                {
                    request.Headers.Add("DPoP", DPoPProofFactory.Create(dpopKey, configuration.DPoPSigningAlgorithm(), "POST", tokenEndpoint, nonce: dpopNonce));
                }
                request.Content = new FormUrlEncodedContent(parameters);

                using var response = await httpClientFactory.CreateClient(IdentifyHttpClient.Name).SendAsync(request, cancellationToken);
                if (!response.IsSuccessStatusCode)
                {
                    var challengedNonce = dpopKey != null && attempt == 1 ? await DPoPNonce.ReadChallengeAsync(response) : null;
                    if (challengedNonce != null)
                    {
                        dpopNonce = challengedNonce;
                        continue;
                    }

                    throw await OAuthErrorResponseException.CreateAsync("token endpoint", response);
                }

                var tokenResponse = new OpenIdConnectMessage(await response.Content.ReadAsStringAsync(cancellationToken));
                // An authorization server without DPoP support ignores the proof and issues a bearer token (RFC 9449 section 5).
                if (dpopKey != null && !string.Equals(tokenResponse.TokenType, "DPoP", StringComparison.OrdinalIgnoreCase))
                {
                    throw new OAuthClientException(string.Format(
                        "The token endpoint returned token_type '{0}', but the token request had a DPoP proof. The access token is not bound to the key.",
                        tokenResponse.TokenType));
                }

                return tokenResponse;
            }
        }
    }
}
