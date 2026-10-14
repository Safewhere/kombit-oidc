using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace WebAppNetCore.OAuth
{
    /// <summary>
    /// Sends token requests to the token endpoint of the discovery document.
    /// </summary>
    public sealed class TokenClient
    {
        private readonly IHttpClientFactory httpClientFactory;
        private readonly IdentifyMetadata identifyMetadata;
        private readonly ClientAuthentication clientAuthentication;

        public TokenClient(IHttpClientFactory httpClientFactory, IdentifyMetadata identifyMetadata, ClientAuthentication clientAuthentication)
        {
            this.httpClientFactory = httpClientFactory;
            this.identifyMetadata = identifyMetadata;
            this.clientAuthentication = clientAuthentication;
        }

        public Task<OpenIdConnectMessage> RedeemCodeAsync(string code, string redirectUri, string codeVerifier, string sessionState, CancellationToken cancellationToken)
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

            return SendAsync(parameters, cancellationToken);
        }

        private async Task<OpenIdConnectMessage> SendAsync(Dictionary<string, string> grantParameters, CancellationToken cancellationToken)
        {
            var metadata = await identifyMetadata.GetAsync(cancellationToken);
            var tokenEndpoint = IdentifyMetadata.RequireEndpoint(metadata.TokenEndpoint, "token_endpoint");

            var parameters = new Dictionary<string, string>(grantParameters);
            using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint);
            clientAuthentication.Apply(request, parameters, metadata);
            request.Content = new FormUrlEncodedContent(parameters);

            using var response = await httpClientFactory.CreateClient(IdentifyHttpClient.Name).SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                throw await OAuthErrorResponseException.CreateAsync("token endpoint", response);
            }

            return new OpenIdConnectMessage(await response.Content.ReadAsStringAsync(cancellationToken));
        }
    }
}
