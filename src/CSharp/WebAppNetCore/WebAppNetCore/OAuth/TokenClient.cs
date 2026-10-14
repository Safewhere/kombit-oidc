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
            string code, string redirectUri, string codeVerifier, string sessionState, ClientSession session, Fault fault, CancellationToken cancellationToken)
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

            return SendAsync("Token request (authorization code)", parameters, session, fault, cancellationToken);
        }

        /// <summary>
        /// Uses the refresh token with the DPoP key of the sign-in. Identify binds the refresh token of a public client to the
        /// key; for a confidential client, client authentication binds it, and the new access token is bound to the proof key.
        /// </summary>
        public Task<OpenIdConnectMessage> RefreshAsync(string refreshToken, ClientSession session, Fault fault, CancellationToken cancellationToken)
        {
            var parameters = new Dictionary<string, string>
            {
                { "grant_type", "refresh_token" },
                { "refresh_token", refreshToken }
            };
            return SendAsync("Token request (refresh token)", parameters, session, fault, cancellationToken);
        }

        private async Task<OpenIdConnectMessage> SendAsync(
            string step, Dictionary<string, string> grantParameters, ClientSession session, Fault fault, CancellationToken cancellationToken)
        {
            var metadata = await identifyMetadata.GetAsync(cancellationToken);
            var tokenEndpoint = IdentifyMetadata.RequireEndpoint(metadata.TokenEndpoint, "token_endpoint");

            DPoPKey dpopKey = null;
            if (configuration.DPoPBindAccessTokens())
            {
                dpopKey = session?.DPoPKey ?? throw new OAuthClientException("The DPoP key of this sign-in is no longer available, for example after a restart. Sign in again.");
            }

            // A fault changes the proof of this request, never the key of the sign-in, except that NewDPoPKeyOnRefresh replaces
            // the key after a successful refresh.
            var htu = tokenEndpoint;
            DPoPKey faultKey = null;
            if (dpopKey != null)
            {
                switch (fault)
                {
                    case Fault.NoDPoPProof:
                        dpopKey = null;
                        break;
                    case Fault.WrongDPoPKey:
                    case Fault.NewDPoPKeyOnRefresh:
                        dpopKey = faultKey = DPoPKey.Create();
                        break;
                    case Fault.SmallDPoPKey:
                        dpopKey = faultKey = DPoPKey.Create(1024);
                        break;
                    case Fault.WrongHtu:
                        htu = metadata.AuthorizationEndpoint;
                        break;
                }
            }

            try
            {
                var tokenResponse = await SendAsync(step, grantParameters, session, fault, metadata, tokenEndpoint, dpopKey, htu, cancellationToken);
                if (fault == Fault.NewDPoPKeyOnRefresh && faultKey != null)
                {
                    // The old key is not disposed, because a concurrent request of the session can still use it.
                    session.DPoPKey = faultKey;
                    faultKey = null;
                }

                return tokenResponse;
            }
            finally
            {
                faultKey?.Dispose();
            }
        }

        private async Task<OpenIdConnectMessage> SendAsync(
            string step,
            Dictionary<string, string> grantParameters,
            ClientSession session,
            Fault fault,
            OpenIdConnectConfiguration metadata,
            string tokenEndpoint,
            DPoPKey dpopKey,
            string htu,
            CancellationToken cancellationToken)
        {
            string dpopNonce = null;
            for (var attempt = 1; ; attempt++)
            {
                // Each attempt has a new client assertion and a new proof, because Identify rejects a replayed jti.
                var parameters = new Dictionary<string, string>(grantParameters);
                using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint);
                var clientAssertion = clientAuthentication.Apply(request, parameters, metadata, fault);
                if (dpopKey != null)
                {
                    request.Headers.Add("DPoP", DPoPProofFactory.Create(dpopKey, configuration.DPoPSigningAlgorithm(), "POST", htu, nonce: dpopNonce));
                }
                request.Content = new FormUrlEncodedContent(parameters);

                using var response = await httpClientFactory.CreateClient(IdentifyHttpClient.Name).SendAsync(request, cancellationToken);
                if (!response.IsSuccessStatusCode)
                {
                    var challengedNonce = dpopKey != null && attempt == 1 ? await DPoPNonce.ReadChallengeAsync(response) : null;
                    if (challengedNonce != null)
                    {
                        session?.Trace.AddExchange(step, request, parameters, clientAssertion, (int)response.StatusCode, "use_dpop_nonce: retry with the server nonce");
                        dpopNonce = challengedNonce;
                        continue;
                    }

                    var error = await OAuthErrorResponseException.CreateAsync("token endpoint", response);
                    session?.Trace.AddExchange(step, request, parameters, clientAssertion, error.StatusCode, error.Error + " " + error.ErrorDescription);
                    throw error;
                }

                var tokenResponse = new OpenIdConnectMessage(await response.Content.ReadAsStringAsync(cancellationToken));
                session?.Trace.AddExchange(step, request, parameters, clientAssertion, (int)response.StatusCode, "token_type=" + tokenResponse.TokenType, new[]
                {
                    ProtocolTrace.Detail("token_type", tokenResponse.TokenType),
                    ProtocolTrace.Detail("expires_in", tokenResponse.ExpiresIn),
                    ProtocolTrace.Detail("scope", tokenResponse.Scope),
                    ProtocolTrace.Detail("refresh_token", string.IsNullOrEmpty(tokenResponse.RefreshToken) ? "(none)" : "(present)"),
                    ProtocolTrace.Detail("id_token", string.IsNullOrEmpty(tokenResponse.IdToken) ? "(none)" : "(present)")
                });

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
