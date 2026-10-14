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

            var descriptor = new SecurityTokenDescriptor
            {
                TokenType = ProofType,
                Claims = claims,
                SigningCredentials = new SigningCredentials(key.SecurityKey, algorithm),
                AdditionalHeaderClaims = new Dictionary<string, object> { ["jwk"] = key.PublicJwk },
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
