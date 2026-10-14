using System;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace WebAppNetCore.OAuth
{
    /// <summary>
    /// Generates a nonce of 43 characters: 32 random bytes, base64url encoded. The default nonce of the handler has about
    /// 115 characters (a timestamp and two GUIDs), and FAPI 2.0 section 5.3.3.2 item 7 limits the nonce to 64 characters.
    /// </summary>
    public sealed class ShortNonceProtocolValidator : OpenIdConnectProtocolValidator
    {
        public ShortNonceProtocolValidator()
        {
            // The same values as the default validator of OpenIdConnectOptions. The handler correlates state itself.
            RequireStateValidation = false;
            NonceLifetime = TimeSpan.FromMinutes(15);
            RequireTimeStampInNonce = false;
        }

        public override string GenerateNonce()
        {
            return Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        }
    }
}
