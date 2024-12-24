using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
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

            var idToken = HttpContext.User.Claims.Where(x => x.Type == OpenIdConnectConstants.IdToken).Select(x => x.Value).FirstOrDefault();

            string authorizationRequest = string.Format("{0}?response_type=id_token&scope={4}&redirect_uri={1}&client_id={2}" +
                                                        "&state={3}&prompt=none" +
                                                        "&nonce={5}"+
                                                        "&id_token_hint={6}",
                configuration.AuthorizationEndpoint(),
                HttpContext.Request.Scheme + "://" + HttpContext.Request.Host + "/Account/ReauthenticationCallBack",
                HttpUtility.UrlEncode(configuration.ClientId()),
                state,
                HttpUtility.UrlEncode(configuration.Scope()),
                nonce,
                idToken);
            return authorizationRequest;
        }

        #region Helpers
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
