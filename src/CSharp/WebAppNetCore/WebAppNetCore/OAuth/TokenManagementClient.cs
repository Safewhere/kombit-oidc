using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace WebAppNetCore.OAuth
{
    /// <summary>
    /// Sends token introspection (RFC 7662) and token revocation (RFC 7009) requests to the endpoints of the discovery document,
    /// with the configured client authentication.
    /// </summary>
    public sealed class TokenManagementClient
    {
        private readonly IHttpClientFactory httpClientFactory;
        private readonly IdentifyMetadata identifyMetadata;
        private readonly ClientAuthentication clientAuthentication;
        private readonly IConfiguration configuration;

        public TokenManagementClient(IHttpClientFactory httpClientFactory, IdentifyMetadata identifyMetadata, ClientAuthentication clientAuthentication, IConfiguration configuration)
        {
            this.httpClientFactory = httpClientFactory;
            this.identifyMetadata = identifyMetadata;
            this.clientAuthentication = clientAuthentication;
            this.configuration = configuration;
        }

        /// <summary>
        /// Introspects the access token and returns the response as indented JSON. IntrospectWithClientSecret authenticates with
        /// client_secret_post instead of the configured method, IntrospectWithoutClientAuthentication sends only client_id, and
        /// IntrospectAsOtherClient authenticates as Testing:OtherClientId.
        /// </summary>
        public async Task<string> IntrospectAsync(string accessToken, ClientSession session, Fault fault, CancellationToken cancellationToken)
        {
            var metadata = await identifyMetadata.GetAsync(cancellationToken);
            var endpoint = IdentifyMetadata.RequireEndpoint(metadata.IntrospectionEndpoint, "introspection_endpoint");
            using var response = await SendAsync("Introspection request", "introspection endpoint", endpoint, accessToken, session, fault, metadata, cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            return ProtocolTrace.FormatJson(body);
        }

        /// <summary>
        /// Revokes the token: the access token, or the refresh token with RevokeRefreshToken. RevokeWithClientSecret authenticates
        /// with client_secret_post instead of the configured method, RevokeWithoutClientAuthentication sends only client_id, and
        /// RevokeAsOtherClient authenticates as Testing:OtherClientId.
        /// </summary>
        public async Task RevokeAsync(string token, ClientSession session, Fault fault, CancellationToken cancellationToken)
        {
            var metadata = await identifyMetadata.GetAsync(cancellationToken);
            var endpoint = IdentifyMetadata.RequireEndpoint(metadata.RevocationEndpoint, "revocation_endpoint");
            using var response = await SendAsync("Revocation request", "revocation endpoint", endpoint, token, session, fault, metadata, cancellationToken);
        }

        private async Task<HttpResponseMessage> SendAsync(
            string step, string endpointName, string endpoint, string token, ClientSession session, Fault fault, OpenIdConnectConfiguration metadata, CancellationToken cancellationToken)
        {
            var tokenTypeHint = fault == Fault.RevokeRefreshToken ? "refresh_token" : "access_token";
            var parameters = new Dictionary<string, string> { { "token", token }, { "token_type_hint", tokenTypeHint } };
            using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
            string clientAssertion = null;
            if (fault == Fault.IntrospectWithClientSecret || fault == Fault.RevokeWithClientSecret)
            {
                parameters["client_id"] = configuration.ClientId();
                parameters["client_secret"] = configuration.ClientSecret();
            }
            else if (fault == Fault.IntrospectAsOtherClient || fault == Fault.RevokeAsOtherClient)
            {
                // Another client with the client key: only private_key_jwt can authenticate as it, because the sample has no
                // secret of the other client. Otherwise the request would fail for the credentials, not for the token.
                if (configuration.TokenAuthnMethod() != "private_key_jwt")
                {
                    throw new OAuthClientException(
                        "The fault " + fault + " needs TokenAuthnMethod private_key_jwt and another connection with the same client keys in Testing:OtherClientId. The request was not sent.");
                }

                clientAssertion = clientAuthentication.Apply(request, parameters, metadata, fault, configuration.OtherClientId());
            }
            else
            {
                clientAssertion = clientAuthentication.Apply(request, parameters, metadata, fault);
            }

            request.Content = new FormUrlEncodedContent(parameters);
            var response = await httpClientFactory.CreateClient(IdentifyHttpClient.Name).SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                var error = await OAuthErrorResponseException.CreateAsync(endpointName, response);
                session?.Trace.AddExchange(step, request, parameters, clientAssertion, error.StatusCode, error.Error + " " + error.ErrorDescription);
                response.Dispose();
                throw error;
            }

            session?.Trace.AddExchange(step, request, parameters, clientAssertion, (int)response.StatusCode, response.Content.Headers.ContentType?.MediaType ?? "(no content)");
            return response;
        }
    }

    public static class AccessTokenInspector
    {
        /// <summary>
        /// The cnf.jkt claim of a JWT access token (RFC 9449 section 6.1), or null.
        /// </summary>
        public static string ReadConfirmationThumbprint(string accessToken)
        {
            var handler = new JsonWebTokenHandler();
            if (string.IsNullOrEmpty(accessToken) || !handler.CanReadToken(accessToken))
            {
                return null;
            }

            var token = handler.ReadJsonWebToken(accessToken);
            return token.TryGetPayloadValue<JsonElement>("cnf", out var confirmation)
                && confirmation.ValueKind == JsonValueKind.Object
                && confirmation.TryGetProperty("jkt", out var jkt)
                && jkt.ValueKind == JsonValueKind.String ? jkt.GetString() : null;
        }
    }
}
