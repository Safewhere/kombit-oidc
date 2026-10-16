using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace WebAppNetCore.OAuth
{
    /// <summary>
    /// Creates DPoP proofs (RFC 9449 section 4.2). Each proof is for one HTTP request and is never sent twice.
    /// </summary>
    public static class DPoPProofFactory
    {
        public const string ProofType = "dpop+jwt";

        /// <summary>
        /// Creates a proof. Give the access token for a request to a protected resource, such as UserInfo, so that the proof has ath.
        /// Give the nonce after a use_dpop_nonce challenge.
        /// </summary>
        public static string Create(DPoPKey key, string algorithm, string httpMethod, string httpUri, string accessToken = null, string nonce = null)
        {
            return Sign(key.SecurityKey, key, algorithm, Claims(httpMethod, httpUri, accessToken, nonce));
        }

        /// <summary>
        /// Creates the proof that a fault asks for, or a correct proof for any other fault: ProofAlgNone (unsigned), ProofHmac
        /// (HS256 with a random key), ProofSignatureOtherKey (the jwk of the key, signed with another key), or ProofWithoutJti.
        /// </summary>
        public static string Create(Fault fault, DPoPKey key, string algorithm, string httpMethod, string httpUri, string accessToken = null, string nonce = null)
        {
            var claims = Claims(httpMethod, httpUri, accessToken, nonce);
            switch (fault)
            {
                case Fault.ProofAlgNone:
                    return FaultJwt.Unsigned(Header(key), claims);

                case Fault.ProofHmac:
                    return FaultJwt.Hmac(Header(key), claims, RandomNumberGenerator.GetBytes(32));

                case Fault.ProofSignatureOtherKey:
                    using (var otherKey = DPoPKey.Create())
                    {
                        return Sign(otherKey.SecurityKey, key, algorithm, claims);
                    }

                case Fault.ProofWithoutJti:
                    claims.Remove("jti");
                    return Sign(key.SecurityKey, key, algorithm, claims);

                default:
                    return Sign(key.SecurityKey, key, algorithm, claims);
            }
        }

        private static Dictionary<string, object> Claims(string httpMethod, string httpUri, string accessToken, string nonce)
        {
            var claims = new Dictionary<string, object>
            {
                ["jti"] = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(16)),
                ["htm"] = httpMethod,
                ["htu"] = HttpUri(httpUri),
                ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            };
            if (accessToken != null)
            {
                claims["ath"] = AccessTokenHash(accessToken);
            }

            if (nonce != null)
            {
                claims["nonce"] = nonce;
            }

            return claims;
        }

        private static Dictionary<string, object> Header(DPoPKey key)
        {
            return new Dictionary<string, object> { ["typ"] = ProofType, ["jwk"] = key.PublicJwk };
        }

        /// <summary>Signs the claims with the signing key; the jwk header is the public key of headerKey.</summary>
        private static string Sign(SecurityKey signingKey, DPoPKey headerKey, string algorithm, Dictionary<string, object> claims)
        {
            var descriptor = new SecurityTokenDescriptor
            {
                TokenType = ProofType,
                Claims = claims,
                SigningCredentials = new SigningCredentials(signingKey, algorithm),
                AdditionalHeaderClaims = new Dictionary<string, object> { ["jwk"] = headerKey.PublicJwk },
                IncludeKeyIdInHeader = false
            };

            // No exp or nbf: the server checks iat.
            return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(descriptor);
        }

        /// <summary>
        /// The htu value: the request URI without query and fragment. Identify compares it with the public URL of the endpoint,
        /// so the sample uses the endpoint URL from the discovery document.
        /// </summary>
        public static string HttpUri(string uri)
        {
            return new Uri(uri).GetLeftPart(UriPartial.Path);
        }

        /// <summary>
        /// The ath value: the base64url SHA-256 hash of the ASCII access token.
        /// </summary>
        public static string AccessTokenHash(string accessToken)
        {
            return Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));
        }
    }
}
