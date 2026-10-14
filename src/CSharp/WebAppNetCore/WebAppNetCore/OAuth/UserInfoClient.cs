using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
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

        public UserInfoClient(IHttpClientFactory httpClientFactory, IdentifyMetadata identifyMetadata)
        {
            this.httpClientFactory = httpClientFactory;
            this.identifyMetadata = identifyMetadata;
        }

        /// <summary>
        /// Returns null when the discovery document has no UserInfo endpoint or when there is no access token, as the handler does.
        /// </summary>
        public async Task<UserInfoResponse> GetAsync(string accessToken, CancellationToken cancellationToken)
        {
            var metadata = await identifyMetadata.GetAsync(cancellationToken);
            if (string.IsNullOrEmpty(metadata.UserInfoEndpoint) || string.IsNullOrEmpty(accessToken))
            {
                return null;
            }

            using var request = new HttpRequestMessage(HttpMethod.Get, metadata.UserInfoEndpoint);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            using var response = await httpClientFactory.CreateClient(IdentifyHttpClient.Name).SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                throw await OAuthErrorResponseException.CreateAsync("UserInfo endpoint", response);
            }

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
