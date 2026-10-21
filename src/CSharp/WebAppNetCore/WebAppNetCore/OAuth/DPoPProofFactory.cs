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
        /// (HS256 with a random key), ProofSignatureOtherKey (the jwk of the key, signed with another key), or a proof without
        /// jti, htm, htu, or iat.
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
                case Fault.ProofWithoutHtm:
                case Fault.ProofWithoutHtu:
                case Fault.ProofWithoutIat:
                    claims.Remove(OmittedClaim(fault));
                    return Sign(key.SecurityKey, key, algorithm, claims);

                case Fault.ProofWrongHtm:
                    claims["htm"] = httpMethod == "POST" ? "GET" : "POST";
                    return Sign(key.SecurityKey, key, algorithm, claims);

                case Fault.ProofHtuPathCase:
                    claims["htu"] = ChangeUri(httpUri, uri => uri.GetLeftPart(UriPartial.Authority) + uri.AbsolutePath.ToUpperInvariant());
                    return Sign(key.SecurityKey, key, algorithm, claims);

                case Fault.ProofHtuWithQuery:
                    claims["htu"] = HttpUri(httpUri) + "?x=1";
                    return Sign(key.SecurityKey, key, algorithm, claims);

                case Fault.ProofHtuHostUpperCase:
                    claims["htu"] = ChangeUri(httpUri, uri => uri.Scheme + "://" + uri.Authority.ToUpperInvariant() + uri.AbsolutePath);
                    return Sign(key.SecurityKey, key, algorithm, claims);

                case Fault.ProofIatFuture:
                case Fault.ProofIatOld:
                case Fault.ProofIatRecent:
                    var seconds = fault == Fault.ProofIatFuture ? 120 : fault == Fault.ProofIatOld ? -90 : -30;
                    claims["iat"] = DateTimeOffset.UtcNow.AddSeconds(seconds).ToUnixTimeSeconds();
                    return Sign(key.SecurityKey, key, algorithm, claims);

                case Fault.ProofNbfFuture:
                    claims["nbf"] = DateTimeOffset.UtcNow.AddSeconds(120).ToUnixTimeSeconds();
                    return Sign(key.SecurityKey, key, algorithm, claims);

                case Fault.ProofTypJwt:
                    return Sign(key.SecurityKey, key.PublicJwk, algorithm, claims, "JWT");

                case Fault.ProofPrivateJwkMembers:
                    return Sign(key.SecurityKey, key.PrivateJwkForFault(), algorithm, claims, ProofType);

                default:
                    return Sign(key.SecurityKey, key, algorithm, claims);
            }
        }

        private static string ChangeUri(string uri, Func<Uri, string> change) => change(new Uri(uri));

        private static string OmittedClaim(Fault fault) => fault switch
        {
            Fault.ProofWithoutHtm => "htm",
            Fault.ProofWithoutHtu => "htu",
            Fault.ProofWithoutIat => "iat",
            _ => "jti"
        };

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
            return Sign(signingKey, headerKey.PublicJwk, algorithm, claims, ProofType);
        }

        private static string Sign(SecurityKey signingKey, IReadOnlyDictionary<string, object> jwk, string algorithm, Dictionary<string, object> claims, string type)
        {
            var descriptor = new SecurityTokenDescriptor
            {
                TokenType = type,
                Claims = claims,
                SigningCredentials = new SigningCredentials(signingKey, algorithm),
                AdditionalHeaderClaims = new Dictionary<string, object> { ["jwk"] = jwk },
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
