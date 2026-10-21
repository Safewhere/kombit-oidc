using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

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
        private readonly DPoPNonceStore dpopNonces;

        public TokenClient(
            IHttpClientFactory httpClientFactory, IdentifyMetadata identifyMetadata, ClientAuthentication clientAuthentication, IConfiguration configuration, DPoPNonceStore dpopNonces)
        {
            this.httpClientFactory = httpClientFactory;
            this.identifyMetadata = identifyMetadata;
            this.clientAuthentication = clientAuthentication;
            this.configuration = configuration;
            this.dpopNonces = dpopNonces;
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
            if (fault == Fault.MissingCodeVerifier)
            {
                parameters.Remove("code_verifier");
            }
            else if (fault == Fault.WrongCodeVerifier)
            {
                // A well-formed verifier (43 characters) that does not match the code_challenge.
                parameters["code_verifier"] = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
            }
            else if (fault == Fault.TokenRedirectUriMismatch)
            {
                // Another path on the same origin, so that a connection can register it and only the match with the
                // authorization request rejects it.
                parameters["redirect_uri"] = new Uri(new Uri(redirectUri), "/other-callback").ToString();
            }
            else if (fault == Fault.TokenWithoutRedirectUri)
            {
                // The authorization request had redirect_uri, so RFC 6749 section 4.1.3 requires it here.
                parameters.Remove("redirect_uri");
            }

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
            if (fault == Fault.RefreshWiderScope)
            {
                // The scope of the sign-in and a scope that it did not grant (RFC 6749 section 6).
                var scopes = (configuration.Scope() ?? string.Empty).Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                parameters["scope"] = string.Join(" ", scopes.Append(NotGrantedScope));
            }

            return SendAsync("Token request (refresh token)", parameters, session, fault, cancellationToken);
        }

        /// <summary>The scope that the faults RefreshWiderScope and ParUnknownScope ask for. No connection has it.</summary>
        public const string NotGrantedScope = "fapi-fault-not-granted";

        /// <summary>
        /// A client credentials grant (RFC 6749 section 4.4) without a sign-in, with a proof of the given key when it is not null.
        /// PasswordGrant sends a password grant (RFC 6749 section 4.3) instead, with a user name that does not exist and a
        /// random password, so that no account is used and only the grant type decides the result.
        /// </summary>
        public async Task<OpenIdConnectMessage> ClientCredentialsAsync(DPoPKey dpopKey, Fault fault, CancellationToken cancellationToken)
        {
            var metadata = await identifyMetadata.GetAsync(cancellationToken);
            var tokenEndpoint = IdentifyMetadata.RequireEndpoint(metadata.TokenEndpoint, "token_endpoint");
            var parameters = fault == Fault.PasswordGrant
                ? new Dictionary<string, string>
                {
                    { "grant_type", "password" },
                    { "username", PasswordGrantUserName },
                    { "password", Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32)) }
                }
                : new Dictionary<string, string> { { "grant_type", "client_credentials" } };
            var step = fault == Fault.PasswordGrant ? "Token request (password)" : "Token request (client credentials)";
            return await SendAsync(step, parameters, null, Fault.None, metadata, tokenEndpoint, dpopKey, tokenEndpoint, cancellationToken);
        }

        /// <summary>The user name of the fault PasswordGrant. No test user has it.</summary>
        public const string PasswordGrantUserName = "fapi-fault-no-such-user";

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
                OpenIdConnectMessage tokenResponse;
                if ((fault == Fault.ReplayDPoPProofOnRefresh && dpopKey != null) || fault == Fault.ReplayClientAssertion)
                {
                    // The result is the response to the second request, which sends the proof or the client assertion of the first again.
                    var replay = new RequestReplay { ReplayProof = fault == Fault.ReplayDPoPProofOnRefresh, ReplayAssertion = fault == Fault.ReplayClientAssertion };
                    await SendAsync(step, grantParameters, session, fault, metadata, tokenEndpoint, dpopKey, htu, cancellationToken, replay);
                    session?.Trace.Add("Fault injection", fault + ": the next refresh request sends the same " + (replay.ReplayProof ? "proof" : "client assertion"));
                    tokenResponse = await SendAsync(step, grantParameters, session, fault, metadata, tokenEndpoint, dpopKey, htu, cancellationToken, replay);
                }
                else if (fault == Fault.WrongDPoPKeyThenRetry && dpopKey != null)
                {
                    // The first request has a proof of a new key; a server that binds the code must reject it without consuming the code.
                    using (var wrongKey = DPoPKey.Create())
                    {
                        try
                        {
                            await SendAsync(step, grantParameters, session, Fault.None, metadata, tokenEndpoint, wrongKey, htu, cancellationToken);
                            session?.Trace.Add("Fault injection", "WrongDPoPKeyThenRetry: the request with a new key succeeded");
                        }
                        catch (OAuthClientException exception)
                        {
                            session?.Trace.Add("Fault injection", "WrongDPoPKeyThenRetry: the request with a new key failed (" + exception.Message + "); the next request uses the key of the sign-in");
                        }
                    }

                    tokenResponse = await SendAsync(step, grantParameters, session, Fault.None, metadata, tokenEndpoint, dpopKey, htu, cancellationToken);
                }
                else
                {
                    tokenResponse = await SendAsync(step, grantParameters, session, fault, metadata, tokenEndpoint, dpopKey, htu, cancellationToken);
                }

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
            CancellationToken cancellationToken,
            RequestReplay replay = null)
        {
            // RedeemAsOtherClient and RefreshAsOtherClient authenticate as another client with the credentials of this one.
            var clientId = fault == Fault.RedeemAsOtherClient || fault == Fault.RefreshAsOtherClient ? configuration.OtherClientId() : null;
            var server = DPoPNonceStore.AuthorizationServer(metadata);
            for (var attempt = 1; ; attempt++)
            {
                // Each attempt has a new client assertion and a new proof, because Identify rejects a replayed jti.
                var dpopNonce = dpopNonces.Get(server);
                var parameters = new Dictionary<string, string>(grantParameters);
                using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint);
                var clientAssertion = clientAuthentication.Apply(request, parameters, metadata, fault, clientId);
                if (fault == Fault.ReplayParAssertionAtToken)
                {
                    // The audience of the PAR assertion is valid here too, so only the jti check can reject it.
                    parameters["client_assertion"] = clientAssertion = session?.PushedClientAssertion
                        ?? throw new OAuthClientException("The fault ReplayParAssertionAtToken has no client assertion of a pushed request. The token request was not sent.");
                }

                if (replay?.ReplayAssertion == true)
                {
                    if (replay.Assertion != null && clientAssertion != null)
                    {
                        parameters["client_assertion"] = clientAssertion = replay.Assertion;
                    }

                    replay.Assertion = clientAssertion;
                }

                if (dpopKey != null)
                {
                    var proof = replay?.ReplayProof == true && replay.Proof != null
                        ? replay.Proof
                        : DPoPProofFactory.Create(fault, dpopKey, configuration.DPoPSigningAlgorithm(), "POST", htu, nonce: dpopNonce);
                    if (replay?.ReplayProof == true)
                    {
                        replay.Proof = proof;
                    }

                    request.Headers.Add("DPoP", proof);
                    if (fault == Fault.TwoProofs)
                    {
                        // A second DPoP header with another valid proof (RFC 9449 section 4.3 allows only one).
                        request.Headers.Add("DPoP", DPoPProofFactory.Create(dpopKey, configuration.DPoPSigningAlgorithm(), "POST", htu, nonce: dpopNonce));
                    }
                }
                request.Content = new FormUrlEncodedContent(parameters);

                using var response = await httpClientFactory.CreateClient(IdentifyHttpClient.Name).SendAsync(request, cancellationToken);
                dpopNonces.Save(server, response);
                if (!response.IsSuccessStatusCode)
                {
                    var challengedNonce = dpopKey != null && attempt == 1 ? await DPoPNonce.ReadChallengeAsync(response) : null;
                    if (challengedNonce != null)
                    {
                        session?.Trace.AddExchange(step, request, parameters, clientAssertion, (int)response.StatusCode, "use_dpop_nonce: retry with the server nonce");
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

        /// <summary>The proof (ReplayDPoPProofOnRefresh) or the client assertion (ReplayClientAssertion) that two requests share.</summary>
        private sealed class RequestReplay
        {
            public bool ReplayProof { get; set; }

            public bool ReplayAssertion { get; set; }

            public string Proof { get; set; }

            public string Assertion { get; set; }
        }
    }
}
