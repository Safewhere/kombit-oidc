using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using NuGet.Common;

namespace WebAppNetCore
{
    public static class OpenIdConnectHelper
    {
        // Keep track of live sessions for back channel logout support
        public static Dictionary<string, bool> LiveSessions = new Dictionary<string, bool>();

        public static readonly string[] IdTokenEncryptedResponseAlgs = { "RSA-OAEP", "RSA-OAEP-256", "A128KW", "A192KW", "A256KW" };
        public static readonly string[] IdTokenEncryptedResponseEnc = { "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM", "A192GCM", "A256GCM" };

        public static string GenerateReauthenticateUri(HttpContext HttpContext, IConfiguration configuration)
        {
            string state = RandomDataBase64url(32);
            string nonce = Guid.NewGuid().ToString("N");

            string authorizationRequest = string.Format("{0}?response_type=code&scope={4}&redirect_uri={1}&client_id={2}" +
                                                        "&state={3}&prompt=none" +
                                                        "&nonce={5}",
                    configuration.AuthorizationEndpoint(),
                    HttpContext.Request.Scheme + "://" + HttpContext.Request.Host + "/Account/ReauthenticationCallBack",
                    HttpUtility.UrlEncode(configuration.ClientId()),
                    state,
                    HttpUtility.UrlEncode(configuration.Scope()),
                    nonce);
            authorizationRequest += "&code_challenge_method=S256";
            string codeVerifier = GenerateCodeVerifier();
            string codeChallenge = GenerateCodeChallenge(codeVerifier);
            authorizationRequest += "&code_challenge=" + codeChallenge;

            return authorizationRequest;
        }

        #region Helpers
        private static string GenerateCodeVerifier()
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

        private static string GenerateCodeChallenge(string codeVerifier)
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

        private static string RandomDataBase64url(uint length)
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] bytes = new byte[length];
            rng.GetBytes(bytes);
            return Base64UrlEncodeNoPadding(bytes);
        }

        /// <summary>
        /// Base64url no-padding encodes the given input buffer.
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
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

        #endregion

        /// <summary>
        /// Decrypts an encrypted JWT (JWE) using the provided decryption credentials.
        /// </summary>
        /// <param name="encryptedToken">The encrypted JWT token string.</param>
        /// <param name="decryptionCredentials">The credentials to use for decryption.</param>
        /// <returns>The decrypted JWT token as a string.</returns>
        /// <exception cref="ArgumentNullException">Thrown when encryptedToken or decryptionCredentials is null.</exception>
        /// <exception cref="ArgumentException">Thrown when the token format is invalid.</exception>
        /// <exception cref="SecurityTokenDecryptionFailedException">Thrown when decryption fails.</exception>
        public static string DecryptToken(string encryptedToken, EncryptingCredentials decryptionCredentials)
        {
            if (string.IsNullOrEmpty(encryptedToken))
                throw new ArgumentNullException(nameof(encryptedToken));

            if (decryptionCredentials == null)
                throw new ArgumentNullException(nameof(decryptionCredentials));

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

        /// <summary>
        /// Gets the content encryption key by unwrapping the encrypted key using the key management algorithm.
        /// </summary>
        private static SecurityKey GetContentEncryptionKey(
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
    }
}
