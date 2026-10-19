using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace WebAppNetCore.OAuth
{
    /// <summary>
    /// Reads a DPoP server nonce challenge. FAPI 2.0 section 5.3.3.1 item 8 requires that the client supports it, although
    /// Identify does not send nonces. The client retries a challenged request once, with a new proof that has the nonce.
    /// DPoPNonceStore keeps the latest nonce of each server for the next requests.
    /// </summary>
    public static class DPoPNonce
    {
        public const string HeaderName = "DPoP-Nonce";
        private const string UseDPoPNonce = "use_dpop_nonce";

        /// <summary>Returns the nonce of the DPoP-Nonce header of any response, or null when the response has none.</summary>
        public static string Read(HttpResponseMessage response)
        {
            return response.Headers.TryGetValues(HeaderName, out var values) ? values.FirstOrDefault(v => !string.IsNullOrEmpty(v)) : null;
        }

        /// <summary>
        /// Returns the nonce of a challenge, or null when the response is not a challenge. An authorization server answers
        /// 400 with error=use_dpop_nonce in the JSON body (RFC 9449 section 8). A resource server answers 401 with
        /// WWW-Authenticate: DPoP error="use_dpop_nonce" (RFC 9449 section 9). Both send the nonce in the DPoP-Nonce header.
        /// </summary>
        public static async Task<string> ReadChallengeAsync(HttpResponseMessage response)
        {
            var nonce = Read(response);
            if (nonce == null)
            {
                return null;
            }

            if (response.StatusCode == HttpStatusCode.BadRequest)
            {
                try
                {
                    using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                    return body.RootElement.ValueKind == JsonValueKind.Object
                        && body.RootElement.TryGetProperty("error", out var error)
                        && error.ValueKind == JsonValueKind.String
                        && error.GetString() == UseDPoPNonce ? nonce : null;
                }
                catch (JsonException)
                {
                    return null;
                }
            }

            if (response.StatusCode == HttpStatusCode.Unauthorized)
            {
                return response.Headers.WwwAuthenticate.Any(c =>
                    string.Equals(c.Scheme, "DPoP", StringComparison.OrdinalIgnoreCase)
                    && AuthenticationHeaderParameters.Read(c.Parameter, "error") == UseDPoPNonce) ? nonce : null;
            }

            return null;
        }
    }
}
