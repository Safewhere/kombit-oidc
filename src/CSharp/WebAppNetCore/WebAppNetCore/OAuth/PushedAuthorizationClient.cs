using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace WebAppNetCore.OAuth
{
    /// <summary>
    /// Sends a pushed authorization request (RFC 9126) to the PAR endpoint of the discovery document. The handler decides when
    /// to push and builds the browser redirect, but the sample sends the request itself: the handler's own push can only use
    /// client_secret, and Identify applies the configured client authentication method at the PAR endpoint.
    /// </summary>
    public sealed class PushedAuthorizationClient
    {
        private const string Step = "Pushed authorization request";

        private readonly IHttpClientFactory httpClientFactory;
        private readonly IdentifyMetadata identifyMetadata;
        private readonly ClientAuthentication clientAuthentication;
        private readonly IConfiguration configuration;
        private readonly DPoPNonceStore dpopNonces;

        public PushedAuthorizationClient(
            IHttpClientFactory httpClientFactory, IdentifyMetadata identifyMetadata, ClientAuthentication clientAuthentication, IConfiguration configuration, DPoPNonceStore dpopNonces)
        {
            this.httpClientFactory = httpClientFactory;
            this.identifyMetadata = identifyMetadata;
            this.clientAuthentication = clientAuthentication;
            this.configuration = configuration;
            this.dpopNonces = dpopNonces;
        }

        public async Task<PushedAuthorizationResult> PushAsync(
            OpenIdConnectMessage authorizationRequest, ClientSession session, Fault fault, CancellationToken cancellationToken)
        {
            var metadata = await identifyMetadata.GetAsync(cancellationToken);
            var parEndpoint = IdentifyMetadata.RequireEndpoint(metadata.PushedAuthorizationRequestEndpoint, "pushed_authorization_request_endpoint");

            // With a proof, Identify binds the code to the proof key, as with dpop_jkt. With both, the keys must be the same.
            var dpopKey = configuration.DPoPSendProofToParEndpoint() ? session?.DPoPKey : null;
            using var faultKey = fault == Fault.ParProofKeyMismatch ? DPoPKey.Create() : null;
            dpopKey = faultKey ?? dpopKey;

            // The PAR endpoint and the token endpoint share the nonce of the authorization server.
            var server = DPoPNonceStore.AuthorizationServer(metadata);
            for (var attempt = 1; ; attempt++)
            {
                var dpopNonce = dpopNonces.Get(server);
                // All authorization parameters of the handler: client_id, response_type, redirect_uri, scope, state, nonce, PKCE, and
                // the parameters that OnRedirectToIdentityProvider added.
                var parameters = authorizationRequest.Parameters.ToDictionary(p => p.Key, p => p.Value);
                ApplyRedirectUriFault(parameters, fault);
                var repeated = ApplyParameterFaults(parameters, fault);
                using var request = new HttpRequestMessage(HttpMethod.Post, parEndpoint);
                // ParWithoutClientAuthentication keeps the client_id of the handler and sends no credentials.
                var clientAssertion = fault == Fault.ParWithoutClientAuthentication ? null : clientAuthentication.Apply(request, parameters, metadata, fault);
                if (dpopKey != null)
                {
                    // ParProofTokenEndpointHtu works with DPoP:SendProofToParEndpoint, which gives the PAR request a proof.
                    var htu = fault == Fault.ParProofTokenEndpointHtu ? IdentifyMetadata.RequireEndpoint(metadata.TokenEndpoint, "token_endpoint") : parEndpoint;
                    request.Headers.Add("DPoP", DPoPProofFactory.Create(dpopKey, configuration.DPoPSigningAlgorithm(), "POST", htu, nonce: dpopNonce));
                }
                request.Content = new FormUrlEncodedContent(parameters.Concat(repeated));

                using var response = await httpClientFactory.CreateClient(IdentifyHttpClient.Name).SendAsync(request, cancellationToken);
                dpopNonces.Save(server, response);
                if (!response.IsSuccessStatusCode)
                {
                    var challengedNonce = dpopKey != null && attempt == 1 ? await DPoPNonce.ReadChallengeAsync(response) : null;
                    if (challengedNonce != null)
                    {
                        session?.Trace.AddExchange(Step, request, parameters, clientAssertion, (int)response.StatusCode, "use_dpop_nonce: retry with the server nonce");
                        continue;
                    }

                    var error = await OAuthErrorResponseException.CreateAsync("PAR endpoint", response);
                    session?.Trace.AddExchange(Step, request, parameters, clientAssertion, error.StatusCode, error.Error + " " + error.ErrorDescription);
                    throw error;
                }

                var result = await ReadResultAsync(response, cancellationToken);
                session?.Trace.AddExchange(Step, request, parameters, clientAssertion, result.StatusCode, "expires_in=" + result.ExpiresIn, new[]
                {
                    ProtocolTrace.Detail("request_uri", result.RequestUri),
                    ProtocolTrace.Detail("expires_in", result.ExpiresIn?.ToString())
                });
                return result;
            }
        }

        /// <summary>
        /// A redirect URI that only starts with the registered one. Only the pushed request has it; the token request keeps the
        /// redirect URI of the handler.
        /// </summary>
        private static void ApplyRedirectUriFault(IDictionary<string, string> parameters, Fault fault)
        {
            if (!parameters.TryGetValue("redirect_uri", out var redirectUri))
            {
                return;
            }

            if (fault == Fault.ParRedirectUriExtraPath)
            {
                parameters["redirect_uri"] = redirectUri.TrimEnd('/') + "/x";
            }
            else if (fault == Fault.ParRedirectUriExtraQuery)
            {
                parameters["redirect_uri"] = QueryHelpers.AddQueryString(redirectUri, "x", "1");
            }
        }

        /// <summary>
        /// The faults of the pushed request parameters. Returns the parameters that the request has a second time
        /// (ParRepeatedParameter); the form dictionary cannot hold them.
        /// </summary>
        private static List<KeyValuePair<string, string>> ApplyParameterFaults(IDictionary<string, string> parameters, Fault fault)
        {
            var repeated = new List<KeyValuePair<string, string>>();
            switch (fault)
            {
                case Fault.ParMissingCodeChallenge:
                    parameters.Remove("code_challenge");
                    break;
                case Fault.ParMissingCodeChallengeMethod:
                    parameters.Remove("code_challenge_method");
                    break;
                case Fault.ParPlainPkce:
                    parameters["code_challenge_method"] = "plain";
                    break;
                case Fault.ParMissingRedirectUri:
                    parameters.Remove("redirect_uri");
                    break;
                case Fault.ParRepeatedParameter:
                    repeated.Add(new KeyValuePair<string, string>("scope", parameters.TryGetValue("scope", out var scope) ? scope : "openid"));
                    break;
                case Fault.ParRequestParameter:
                    // An unsigned request object with the same parameters. Identify does not support request objects in PAR.
                    parameters["request"] = FaultJwt.Unsigned(
                        new Dictionary<string, object> { ["typ"] = "oauth-authz-req+jwt" },
                        parameters.Where(p => p.Key != "client_assertion" && p.Key != "client_assertion_type").ToDictionary(p => p.Key, p => (object)p.Value));
                    break;
                case Fault.ParNestedRequestUri:
                    parameters["request_uri"] = "urn:ietf:params:oauth:request_uri:nested-in-the-pushed-request";
                    break;
                case Fault.UnknownResponseTypeComponent:
                    parameters["response_type"] = "code unknown";
                    break;
                case Fault.ResponseTypeWithToken:
                    parameters["response_type"] = "code token";
                    break;
            }

            return repeated;
        }

        private static async Task<PushedAuthorizationResult> ReadResultAsync(HttpResponseMessage response, CancellationToken cancellationToken)
        {
            using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
            if (!body.RootElement.TryGetProperty("request_uri", out var requestUri) || requestUri.ValueKind != JsonValueKind.String)
            {
                throw new OAuthClientException("The PAR response has no request_uri.");
            }

            int? expiresIn = body.RootElement.TryGetProperty("expires_in", out var expires) && expires.TryGetInt32(out var seconds) ? seconds : null;
            return new PushedAuthorizationResult(requestUri.GetString(), expiresIn, (int)response.StatusCode);
        }
    }

    public sealed class PushedAuthorizationResult
    {
        public PushedAuthorizationResult(string requestUri, int? expiresIn, int statusCode)
        {
            RequestUri = requestUri;
            ExpiresIn = expiresIn;
            StatusCode = statusCode;
        }

        public string RequestUri { get; }

        /// <summary>The lifetime of the request_uri in seconds. FAPI 2.0 requires less than 600.</summary>
        public int? ExpiresIn { get; }

        /// <summary>RFC 9126 section 2.2 requires 201 Created.</summary>
        public int StatusCode { get; }
    }
}
