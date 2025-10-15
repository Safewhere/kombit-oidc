using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Web;
using Microsoft.IdentityModel.Tokens;

namespace KomitWpfOIDC
{
    public class OpenIdConnectHelper
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

        public static (string Url, string CodeVerifier, string State) GenerateReauthenticateUri(string? acrValues = null, int? maxAgeSec = null)
        {
            string state = RandomDataBase64url(32);
            string nonce = Guid.NewGuid().ToString("N");

            string authorizationRequest = string.Format("{0}?response_type=code&scope={4}&redirect_uri={1}&client_id={2}" +
                                                        "&state={3}" +
                                                        "&nonce={5}",
                    ConfigurationExtensions.AuthorizationEndpoint,
                    Uri.EscapeDataString(ConfigurationExtensions.LoopbackRedirect),
                    Uri.EscapeDataString(ConfigurationExtensions.ClientId),
                    state,
                    Uri.EscapeDataString(ConfigurationExtensions.Scope),
                    nonce);
            authorizationRequest += "&code_challenge_method=S256";
            string codeVerifier = GenerateCodeVerifier();
            string codeChallenge = GenerateCodeChallenge(codeVerifier);
            authorizationRequest += "&code_challenge=" + codeChallenge;

            if (!string.IsNullOrWhiteSpace(acrValues))
                authorizationRequest += $"&acr_values={Uri.EscapeDataString(acrValues)}";

            if (maxAgeSec > 0)
                authorizationRequest += $"&max_age={maxAgeSec}";

            return (authorizationRequest, codeVerifier, state);
        }

        public static X509Certificate2? GetDecryptionCertificate()
        {
            var pfxPath = ConfigurationExtensions.IdTokenDecryptionCertPath;
            var pfxPassword = ConfigurationExtensions.IdTokenDecryptionCertPassword;
            if (string.IsNullOrWhiteSpace(pfxPath)) return null;

            if (!System.IO.File.Exists(pfxPath))
                throw new InvalidOperationException($"PFX not found: {pfxPath}");

            var flags =
                X509KeyStorageFlags.MachineKeySet |
                X509KeyStorageFlags.PersistKeySet |
                X509KeyStorageFlags.Exportable;

            var cert = new X509Certificate2(pfxPath, pfxPassword ?? string.Empty, flags);

            if (!cert.HasPrivateKey)
                throw new InvalidOperationException("Certificate does not contain a private key. Decryption requires private key.");
            return cert;
        }
        public static string DecryptToken(string encryptedToken, EncryptingCredentials decryptionCredentials)
        {
            if (string.IsNullOrWhiteSpace(encryptedToken))
                throw new ArgumentNullException(nameof(encryptedToken));
            if (decryptionCredentials == null)
                throw new ArgumentNullException(nameof(decryptionCredentials));
            if (decryptionCredentials.Key == null)
                throw new ArgumentException("EncryptingCredentials must contain a valid SecurityKey.", nameof(decryptionCredentials));

            try
            {
                // Parse the JWE token parts
                var tokenParts = encryptedToken.Split('.');
                if (tokenParts.Length != 5)
                    throw new ArgumentException("Invalid JWE token format. Expected 5 parts separated by '.'", nameof(encryptedToken));

                var encodedHeader = tokenParts[0];
                var encryptedKey = tokenParts[1];
                var initializationVector = tokenParts[2];
                var ciphertext = tokenParts[3];
                var authenticationTag = tokenParts[4];

                // Decode the header to get encryption algorithm information
                var headerJson = Base64UrlEncoder.Decode(encodedHeader);
                var header = JwtHeader.Base64UrlDeserialize(encodedHeader);

                // Get the encryption algorithm and key management algorithm from header
                var encryptionAlgorithm = header.Enc;
                var keyManagementAlgorithm = header.Alg;

                // Set up crypto provider factory
                var cryptoProviderFactory = new IdentifyCryptoProviderFactory();

                // Unwrap the content encryption key
                SecurityKey contentEncryptionKey = GetContentEncryptionKey(
                    decryptionCredentials.Key,
                    keyManagementAlgorithm,
                    encryptionAlgorithm,
                    encryptedKey,
                    cryptoProviderFactory);

                // Decrypt the payload
                using (var decryptionProvider = cryptoProviderFactory.CreateAuthenticatedEncryptionProvider(contentEncryptionKey, encryptionAlgorithm))
                {
                    if (decryptionProvider == null)
                        throw new SecurityTokenDecryptionFailedException("Failed to create decryption provider.");

                    var ivBytes = Base64UrlEncoder.DecodeBytes(initializationVector);
                    var ciphertextBytes = Base64UrlEncoder.DecodeBytes(ciphertext);
                    var authTagBytes = Base64UrlEncoder.DecodeBytes(authenticationTag);
                    var aadBytes = Encoding.ASCII.GetBytes(encodedHeader);

                    var decryptedBytes = decryptionProvider.Decrypt(ciphertextBytes, aadBytes, ivBytes, authTagBytes);
                    return Encoding.UTF8.GetString(decryptedBytes);
                }
            }
            catch (Exception ex)
            {
                throw new SecurityTokenDecryptionFailedException("Failed to decrypt the JWT token.", ex);
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
