using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using Serilog;

namespace KombitWpfOIDC
{
    public static class OpenIdConnectHelper
    {
        public static string? GetJwtHeader(string? token)
        {
            if (string.IsNullOrWhiteSpace(token)) return null;
            var parts = token.Split('.');
            if (parts.Length < 2) return null;
            return DecodeBase64Url(parts[0]);
        }
        public static (string HeaderJson, string PayloadJson)? GetJwtInfor(string? token)
        {
            string headerJson = string.Empty, payloadJson = string.Empty;
            if (string.IsNullOrWhiteSpace(token)) return null;
            try
            {
                var parts = token.Split('.');
                if (parts.Length < 2) return null;
                headerJson = PrettyPrint(DecodeBase64Url(parts[0]) ?? string.Empty);
                payloadJson = PrettyPrint(DecodeBase64Url(parts[1]) ?? string.Empty);
            }
            catch { }
            return (headerJson, payloadJson);
        }
        public static string? DecodeBase64Url(string? input)
        {
            if (string.IsNullOrWhiteSpace(input)) return null;
            string s = input.Replace('-', '+').Replace('_', '/');
            switch (s.Length % 4)
            {
                case 2: s += "=="; break;
                case 3: s += "="; break;
                case 0: break;
                default: return null;
            }
            try
            {
                var bytes = Convert.FromBase64String(s);
                return Encoding.UTF8.GetString(bytes);
            }
            catch { return null; }
        }

        public static async Task<(string Url, string CodeVerifier, string State)> GenerateReauthenticateUri(string? acrValues = null, int? maxAgeSec = null, bool forceLogin = false, bool isPassive = false)
        {
            Log.Debug("GenerateReauthenticateUri(acr={Acr}, max_age={Max})", acrValues, maxAgeSec);
            string state = RandomDataBase64url(32);
            string nonce = Guid.NewGuid().ToString("N");
            string codeVerifier = GenerateCodeVerifier();
            string codeChallenge = GenerateCodeChallenge(codeVerifier);

            var parameters = new Dictionary<string, string>
            {
                { "response_type", "code" },
                { "client_id", ConfigurationExtensions.ClientId },
                { "scope", ConfigurationExtensions.Scope },
                { "redirect_uri", ConfigurationExtensions.LoopbackRedirect },
                { "state", state },
                { "nonce", nonce },
                { "code_challenge", codeChallenge },
                { "code_challenge_method", "S256" }
            };

            if (!string.IsNullOrWhiteSpace(acrValues))
                parameters.Add("acr_values", acrValues);

            if (maxAgeSec > 0)
                parameters.Add("max_age", maxAgeSec.ToString());

            if (forceLogin)
                parameters.Add("prompt", "login");
            else if (isPassive)
                parameters.Add("prompt", "none");

            LoggerConfig.InfoAsJson("Parameters", parameters);

            if (ConfigurationExtensions.AuthorizationEndpointMethod?.ToUpper() == "POST")
            {
                using var client = new HttpClient();
                var content = new FormUrlEncodedContent(parameters);
                var response = await client.PostAsync(ConfigurationExtensions.AuthorizationEndpoint, content);
                string url = response.Headers.Location?.ToString() ?? ConfigurationExtensions.AuthorizationEndpoint;
                Log.Debug("Auth method POST, Location: {Url}", url);
                return (url, codeVerifier, state);
            }
            else
            {
                var query = string.Join("&", parameters.Select(p => $"{p.Key}={Uri.EscapeDataString(p.Value)}"));
                string url = $"{ConfigurationExtensions.AuthorizationEndpoint}?{query}";
                Log.Debug("Auth method GET, URL: {Url}", url);
                return (url, codeVerifier, state);
            }
        }

        public static SecurityKey GetContentEncryptionKey(
            SecurityKey keyEncryptionKey,
            string keyManagementAlgorithm,
            string contentEncryptionAlgorithm,
            string encryptedKey,
            CryptoProviderFactory cryptoProviderFactory)
        {
            // For direct key agreement algorithms, use the key encryption key directly
            if (System.IdentityModel.Tokens.Jwt.JwtConstants.DirectKeyUseAlg.Equals(keyManagementAlgorithm))
            {
                return keyEncryptionKey;
            }

            // For key wrapping algorithms, unwrap the content encryption key
            if (string.IsNullOrEmpty(encryptedKey))
                throw new SecurityTokenDecryptionFailedException("Encrypted key is required for key wrapping algorithms.");

            var keyWrapProvider = cryptoProviderFactory.CreateKeyWrapProvider(keyEncryptionKey, keyManagementAlgorithm);
            if (keyWrapProvider == null)
                throw new SecurityTokenDecryptionFailedException($"Failed to create key wrap provider for algorithm: {keyManagementAlgorithm}");

            var encryptedKeyBytes = Base64UrlEncoder.DecodeBytes(encryptedKey);
            var unwrappedKeyBytes = keyWrapProvider.UnwrapKey(encryptedKeyBytes);

            return new SymmetricSecurityKey(unwrappedKeyBytes);
        }

        public static string PrettyPrint(string json)
        {
            using var doc = JsonDocument.Parse(json);
            var opts = new JsonSerializerOptions
            {
                WriteIndented = true,
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            };
            return JsonSerializer.Serialize(doc.RootElement, opts);
        }

        public static string GenerateCodeVerifier()
        {
            int length = 43;
            using (var rng = new RNGCryptoServiceProvider())
            {
                var randomBytes = new byte[length];
                rng.GetBytes(randomBytes);

                // Convert to a Base64 URL-safe string
                string base64UrlString = Base64UrlEncode(randomBytes);

                // Trim or extend the string to the desired length
                return base64UrlString.Substring(0, Math.Min(base64UrlString.Length, length));
            }
        }

        public static string GenerateCodeChallenge(string codeVerifier)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));

                return Base64UrlEncode(hashBytes);
            }
        }
        private static string Base64UrlEncode(byte[] input)
        {
            return Convert.ToBase64String(input)
                .TrimEnd('=')   // Remove padding
                .Replace('+', '-') // Replace '+' with '-'
                .Replace('/', '_'); // Replace '/' with '_'
        }
        public static string RandomDataBase64url(uint length)
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] bytes = new byte[length];
            rng.GetBytes(bytes);
            return Base64UrlEncodeNoPadding(bytes);
        }
        private static string Base64UrlEncodeNoPadding(byte[] buffer)
        {
            string base64 = Convert.ToBase64String(buffer);

            // Converts base64 to base64url.
            base64 = base64.Replace("+", "-");
            base64 = base64.Replace("/", "_");
            // Strips padding.
            base64 = base64.Replace("=", "");

            return base64;
        }
    }
}
