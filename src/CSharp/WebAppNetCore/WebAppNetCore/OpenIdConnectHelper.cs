using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

namespace WebAppNetCore
{
    public static class OpenIdConnectHelper
    {
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
    }
}
