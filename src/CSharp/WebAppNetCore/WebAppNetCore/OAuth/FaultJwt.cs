using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace WebAppNetCore.OAuth
{
    /// <summary>
    /// Builds JWTs that the token handler does not create: unsigned (alg none), or signed with HS256 and a key of any size, as
    /// client_secret_jwt uses the client secret. Only fault injection uses it.
    /// </summary>
    public static class FaultJwt
    {
        public static string Unsigned(IDictionary<string, object> header, IDictionary<string, object> payload)
        {
            header["alg"] = "none";
            return Encode(header) + "." + Encode(payload) + ".";
        }

        public static string Hmac(IDictionary<string, object> header, IDictionary<string, object> payload, byte[] key)
        {
            header["alg"] = SecurityAlgorithms.HmacSha256;
            var signingInput = Encode(header) + "." + Encode(payload);
            using var hmac = new HMACSHA256(key);
            return signingInput + "." + Base64UrlEncoder.Encode(hmac.ComputeHash(Encoding.ASCII.GetBytes(signingInput)));
        }

        private static string Encode(IDictionary<string, object> members)
        {
            return Base64UrlEncoder.Encode(JsonSerializer.SerializeToUtf8Bytes(members));
        }
    }
}
