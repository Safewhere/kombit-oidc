using System;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace WebAppNetCore.OAuth
{
    /// <summary>
    /// Generates a nonce of 43 characters by default: random bytes, base64url encoded. The default nonce of the handler has about
    /// 115 characters (a timestamp and two GUIDs), and FAPI 2.0 section 5.3.3.2 item 7 limits the nonce to 64 characters.
    /// Testing:NonceLength selects up to 64 characters, so that a live test can show that Identify accepts the longest nonce.
    /// </summary>
    public sealed class ShortNonceProtocolValidator : OpenIdConnectProtocolValidator
    {
        public const int DefaultNonceLength = 43;
        public const int MaximumNonceLength = 64;

        private readonly int nonceLength;

        public ShortNonceProtocolValidator(int nonceLength = DefaultNonceLength)
        {
            if (nonceLength < DefaultNonceLength || nonceLength > MaximumNonceLength)
            {
                throw new ArgumentOutOfRangeException(nameof(nonceLength), nonceLength, "The nonce length must be from 43 to 64 characters.");
            }

            this.nonceLength = nonceLength;
            // The same values as the default validator of OpenIdConnectOptions. The handler correlates state itself.
            RequireStateValidation = false;
            NonceLifetime = TimeSpan.FromMinutes(15);
            RequireTimeStampInNonce = false;
        }

        public override string GenerateNonce()
        {
            // 48 random bytes give 64 base64url characters; the nonce keeps the first nonceLength of them.
            return Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(48)).Substring(0, nonceLength);
        }
    }
}
