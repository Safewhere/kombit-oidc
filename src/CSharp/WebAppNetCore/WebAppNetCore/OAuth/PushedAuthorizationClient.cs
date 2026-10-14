using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
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

        public PushedAuthorizationClient(IHttpClientFactory httpClientFactory, IdentifyMetadata identifyMetadata, ClientAuthentication clientAuthentication, IConfiguration configuration)
        {
            this.httpClientFactory = httpClientFactory;
            this.identifyMetadata = identifyMetadata;
            this.clientAuthentication = clientAuthentication;
            this.configuration = configuration;
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

            string dpopNonce = null;
            for (var attempt = 1; ; attempt++)
            {
                // All authorization parameters of the handler: client_id, response_type, redirect_uri, scope, state, nonce, PKCE, and
                // the parameters that OnRedirectToIdentityProvider added.
                var parameters = authorizationRequest.Parameters.ToDictionary(p => p.Key, p => p.Value);
                using var request = new HttpRequestMessage(HttpMethod.Post, parEndpoint);
                var clientAssertion = clientAuthentication.Apply(request, parameters, metadata, fault);
                if (dpopKey != null)
                {
                    request.Headers.Add("DPoP", DPoPProofFactory.Create(dpopKey, configuration.DPoPSigningAlgorithm(), "POST", parEndpoint, nonce: dpopNonce));
                }
                request.Content = new FormUrlEncodedContent(parameters);

                using var response = await httpClientFactory.CreateClient(IdentifyHttpClient.Name).SendAsync(request, cancellationToken);
                if (!response.IsSuccessStatusCode)
                {
                    var challengedNonce = dpopKey != null && attempt == 1 ? await DPoPNonce.ReadChallengeAsync(response) : null;
                    if (challengedNonce != null)
                    {
                        session?.Trace.AddExchange(Step, request, parameters, clientAssertion, (int)response.StatusCode, "use_dpop_nonce: retry with the server nonce");
                        dpopNonce = challengedNonce;
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
