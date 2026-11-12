using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace WebAppNetCore.OAuth
{
    /// <summary>
    /// A failure in the OAuth processing of the sample. The message contains no secrets, so the error page can show it.
    /// </summary>
    public class OAuthClientException : Exception
    {
        public OAuthClientException(string message)
            : base(message)
        {
        }
    }

    /// <summary>
    /// An OAuth error response (RFC 6749 section 5.2) from an Identify endpoint.
    /// </summary>
    public sealed class OAuthErrorResponseException : OAuthClientException
    {
        public OAuthErrorResponseException(string endpointName, int statusCode, string error, string errorDescription)
            : base(string.Format("The {0} returned HTTP {1}: {2}{3}", endpointName, statusCode,
                string.IsNullOrEmpty(error) ? "no OAuth error code" : error,
                string.IsNullOrEmpty(errorDescription) ? string.Empty : " (" + errorDescription + ")"))
        {
            EndpointName = endpointName;
            StatusCode = statusCode;
            Error = error;
            ErrorDescription = errorDescription;
        }

        public string EndpointName { get; }

        public int StatusCode { get; }

        public string Error { get; }

        public string ErrorDescription { get; }

        /// <summary>
        /// Reads the error from the JSON body, or from the WWW-Authenticate header (RFC 6750 section 3) when the body has none.
        /// </summary>
        public static async Task<OAuthErrorResponseException> CreateAsync(string endpointName, HttpResponseMessage response)
        {
            string error = null;
            string errorDescription = null;
            var body = await response.Content.ReadAsStringAsync();
            try
            {
                using var json = JsonDocument.Parse(body);
                if (json.RootElement.ValueKind == JsonValueKind.Object)
                {
                    error = ReadString(json.RootElement, "error");
                    errorDescription = ReadString(json.RootElement, "error_description");
                }
            }
            catch (JsonException)
            {
                // Not a JSON error response.
            }

            if (string.IsNullOrEmpty(error))
            {
                foreach (var challenge in response.Headers.WwwAuthenticate)
                {
                    error = AuthenticationHeaderParameters.Read(challenge.Parameter, "error");
                    errorDescription = AuthenticationHeaderParameters.Read(challenge.Parameter, "error_description");
                    if (!string.IsNullOrEmpty(error))
                    {
                        break;
                    }
                }
            }

            return new OAuthErrorResponseException(endpointName, (int)response.StatusCode, error, errorDescription);
        }

        private static string ReadString(JsonElement element, string name)
        {
            return element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
        }
    }
}
