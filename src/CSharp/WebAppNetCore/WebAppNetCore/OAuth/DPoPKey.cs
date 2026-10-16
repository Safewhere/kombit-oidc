using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace WebAppNetCore.OAuth
{
    /// <summary>
    /// The RSA key that signs the DPoP proofs of one sign-in (RFC 9449). Identify accepts RSA keys of at least 2048 bits.
    /// </summary>
    public sealed class DPoPKey : IDisposable
    {
        public const int DefaultKeySizeInBits = 2048;

        private readonly RSA rsa;

        private DPoPKey(RSA rsa)
        {
            this.rsa = rsa;
            var parameters = rsa.ExportParameters(includePrivateParameters: false);
            var n = Base64UrlEncoder.Encode(parameters.Modulus);
            var e = Base64UrlEncoder.Encode(parameters.Exponent);

            // Only the public members, so that the proof header never carries the private key.
            PublicJwk = new Dictionary<string, object> { ["kty"] = "RSA", ["n"] = n, ["e"] = e };
            Thumbprint = ComputeThumbprint(n, e);
            SecurityKey = new RsaSecurityKey(rsa);
        }

        public static DPoPKey Create(int keySizeInBits = DefaultKeySizeInBits)
        {
            return new DPoPKey(RSA.Create(keySizeInBits));
        }

        public RsaSecurityKey SecurityKey { get; }

        /// <summary>The jwk header of the proofs.</summary>
        public IReadOnlyDictionary<string, object> PublicJwk { get; }

        /// <summary>The JWK SHA-256 thumbprint: the dpop_jkt parameter and the cnf.jkt claim of a bound access token.</summary>
        public string Thumbprint { get; }

        public int KeySizeInBits => rsa.KeySize;

        /// <summary>
        /// The jwk with the private members, for the fault ProofPrivateJwkMembers only. A correct proof never carries it.
        /// </summary>
        public IReadOnlyDictionary<string, object> PrivateJwkForFault()
        {
            var p = rsa.ExportParameters(includePrivateParameters: true);
            return new Dictionary<string, object>
            {
                ["kty"] = "RSA", ["n"] = Base64UrlEncoder.Encode(p.Modulus), ["e"] = Base64UrlEncoder.Encode(p.Exponent),
                ["d"] = Base64UrlEncoder.Encode(p.D), ["p"] = Base64UrlEncoder.Encode(p.P), ["q"] = Base64UrlEncoder.Encode(p.Q),
                ["dp"] = Base64UrlEncoder.Encode(p.DP), ["dq"] = Base64UrlEncoder.Encode(p.DQ), ["qi"] = Base64UrlEncoder.Encode(p.InverseQ)
            };
        }

        /// <summary>
        /// Computes the RFC 7638 thumbprint of an RSA key: the SHA-256 hash of the required members in lexicographic order, without whitespace.
        /// </summary>
        public static string ComputeThumbprint(string n, string e)
        {
            var canonicalJwk = "{\"e\":\"" + e + "\",\"kty\":\"RSA\",\"n\":\"" + n + "\"}";
            return Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalJwk)));
        }

        public void Dispose()
        {
            rsa.Dispose();
        }
    }
}
