using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace WebAppNetCore.EmergencyCredential
{
    public sealed class CredentialVerifier
    {
        public const string Profile = "us39805-ec-v1";
        public const string TokenType = "ch2-emergency-webauthn+jwt";
        private readonly EmergencyOptions options;
        public CredentialVerifier(EmergencyOptions configuration)
        {
            options = configuration;
        }

        public VerifiedCredential Verify(string compact, string trustedKeys, DateTimeOffset now)
        {
            try
            {
                if (compact == null || compact.Length > 65536)
                {
                    throw StrictJson.Bad();
                }
                string[] parts = compact.Split('.');
                if (parts.Length != 5)
                {
                    throw StrictJson.Bad();
                }
                JsonElement outer = Decode(parts[0]);
                StrictJson.Members(outer, "alg", "enc", "kid", "cty", "typ");
                if (StrictJson.Text(outer, "alg") != "RSA-OAEP" || StrictJson.Text(outer, "enc") != "A256CBC-HS512"
                    || StrictJson.Text(outer, "kid") != options.EncryptionKeyId || StrictJson.Text(outer, "cty") != "JWT"
                    || (outer.TryGetProperty("typ", out JsonElement outerType) && outerType.GetString() != TokenType))
                {
                    throw StrictJson.Bad();
                }
                using RSA encryption = RSA.Create();
                encryption.ImportFromPem(ReadKey(options.EncryptionPrivateKeyFile));
                if (encryption.KeySize < 2048 || encryption.KeySize > 4096)
                {
                    throw StrictJson.Bad();
                }
                string inner = new JsonWebTokenHandler().DecryptToken(new JsonWebToken(compact), new TokenValidationParameters
                {
                    TokenDecryptionKey = new RsaSecurityKey(encryption) { KeyId = options.EncryptionKeyId },
                    CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
                });
                string[] signed = inner.Split('.');
                if (signed.Length != 3)
                {
                    throw StrictJson.Bad();
                }
                JsonElement header = Decode(signed[0]);
                JsonElement payload = Decode(signed[1]);
                StrictJson.Members(header, "alg", "kid", "typ");
                if (StrictJson.Text(header, "alg") != "ES256" || StrictJson.Text(header, "typ") != TokenType)
                {
                    throw StrictJson.Bad();
                }
                string keyId = StrictJson.Text(header, "kid");
                JsonElement keys = ValidateKeys(trustedKeys);
                JsonElement signing = keys.GetProperty("keys").EnumerateArray().Single(key => StrictJson.Text(key, "kid") == keyId);
                JsonWebKey key = new JsonWebKey(signing.GetRawText());
                new JwtSecurityTokenHandler { MapInboundClaims = false }.ValidateToken(inner, new TokenValidationParameters
                {
                    IssuerSigningKey = key,
                    ValidateIssuerSigningKey = true,
                    RequireSignedTokens = true,
                    ValidAlgorithms = new[] { "ES256" },
                    ValidateIssuer = true,
                    ValidIssuer = options.Issuer,
                    ValidateAudience = true,
                    ValidAudience = options.Audience,
                    RequireAudience = true,
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                    ClockSkew = TimeSpan.Zero,
                    LifetimeValidator = (nbf, exp, token, parameters) => nbf.HasValue && exp.HasValue && nbf.Value <= now.UtcDateTime && exp.Value > now.UtcDateTime
                }, out SecurityToken validated);
                if (StrictJson.Text(payload, "aud") != options.Audience || StrictJson.Text(payload, "iss") != options.Issuer
                    || StrictJson.Text(payload, "profile_version") != Profile)
                {
                    throw StrictJson.Bad();
                }
                long issued = StrictJson.Integer(payload, "iat"), notBefore = StrictJson.Integer(payload, "nbf"), expires = StrictJson.Integer(payload, "exp");
                if (issued > now.ToUnixTimeSeconds() || notBefore > now.ToUnixTimeSeconds() || notBefore < issued
                    || expires <= now.ToUnixTimeSeconds() || expires <= issued || expires - issued > 30 * 86400)
                {
                    throw StrictJson.Bad();
                }
                JsonElement source = payload.GetProperty("source"), webauthn = payload.GetProperty("webauthn");
                if (StrictJson.Text(source, "protocol") != "oidc" || StrictJson.Text(source, "issuer") != options.NormalIssuer
                    || StrictJson.Text(webauthn, "rp_id") != options.RelyingPartyId || StrictJson.Text(webauthn, "origin") != options.Origin
                    || StrictJson.Text(webauthn, "hardware_policy") != "poc-up")
                {
                    throw StrictJson.Bad();
                }
                long accepted = StrictJson.Integer(source, "accepted_at");
                if (accepted > issued || accepted < issued - 86400)
                {
                    throw StrictJson.Bad();
                }
                byte[] credentialId = StrictJson.Bytes(StrictJson.Text(webauthn, "credential_id", 2048), 1024);
                byte[] handle = StrictJson.Bytes(StrictJson.Text(webauthn, "user_handle", 128), 64);
                long counter = StrictJson.Integer(webauthn, "sign_count");
                if (counter < 0 || counter > uint.MaxValue)
                {
                    throw StrictJson.Bad();
                }
                byte[] cose = Cose(payload.GetProperty("cnf").GetProperty("jwk"), StrictJson.Integer(webauthn, "cose_alg"));
                VerifiedCredential result = new VerifiedCredential
                {
                    Id = StrictJson.Text(payload, "jti", 128),
                    Subject = StrictJson.Text(payload, "sub"),
                    SourceIssuer = options.NormalIssuer,
                    SourceReference = StrictJson.Text(source, "token_reference"),
                    Issued = issued,
                    Expires = expires,
                    CredentialId = StrictJson.Encode(credentialId),
                    UserHandle = StrictJson.Encode(handle),
                    CoseKey = StrictJson.Encode(cose),
                    Counter = (uint)counter,
                    Digest = StrictJson.Hash(compact)
                };
                JsonElement claims = payload.GetProperty("claims_snapshot");
                if (claims.ValueKind != JsonValueKind.Array || claims.GetArrayLength() > 200)
                {
                    throw StrictJson.Bad();
                }
                foreach (JsonElement claim in claims.EnumerateArray())
                {
                    StrictJson.Members(claim, "type", "value", "value_type", "name_format");
                    string type = StrictJson.Text(claim, "type", 2048);
                    if (!claim.TryGetProperty("value", out JsonElement claimValue) || claimValue.ValueKind != JsonValueKind.String || claimValue.GetString().Length > 16384)
                    {
                        throw StrictJson.Bad();
                    }
                    string value = claimValue.GetString();
                    result.Claims.Add(new SnapshotClaim { Type = type, Value = value, ValueType = StrictJson.Text(claim, "value_type", 256) });
                }
                return result;
            }
            catch (Exception exception) when (!(exception is EmergencyFault)) { throw new EmergencyFault(400, "credential_rejected"); }
        }

        public static JsonElement ValidateKeys(string json)
        {
            JsonElement root = StrictJson.Parse(json);
            StrictJson.Members(root, "keys");
            JsonElement keys = root.GetProperty("keys");
            if (keys.ValueKind != JsonValueKind.Array || keys.GetArrayLength() < 1 || keys.GetArrayLength() > 8)
            {
                throw StrictJson.Bad();
            }
            HashSet<string> ids = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonElement key in keys.EnumerateArray())
            {
                StrictJson.Members(key, "kty", "crv", "x", "y", "kid", "alg", "use");
                if (StrictJson.Text(key, "kty") != "EC" || StrictJson.Text(key, "crv") != "P-256"
                    || StrictJson.Text(key, "alg") != "ES256" || StrictJson.Text(key, "use") != "sig"
                    || !ids.Add(StrictJson.Text(key, "kid", 128)) || StrictJson.Bytes(StrictJson.Text(key, "x"), 32).Length != 32
                    || StrictJson.Bytes(StrictJson.Text(key, "y"), 32).Length != 32)
                {
                    throw StrictJson.Bad();
                }
            }
            return root;
        }
        public string KeyFingerprint()
        {
            using RSA key = RSA.Create();
            key.ImportFromPem(ReadKey(options.EncryptionPrivateKeyFile));
            return StrictJson.Hash(Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
        }
        private string ReadKey(string path)
        {
            if (new FileInfo(path).Length > 65536)
            {
                throw StrictJson.Bad();
            }
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException("Emergency key protection requires Windows for this PoC.");
            }
            byte[] entropy = SHA256.HashData(Encoding.UTF8.GetBytes("OidcSample.Emergency.EncryptionKey.v1|" + options.Audience));
            return new UTF8Encoding(false, true).GetString(ProtectedData.Unprotect(File.ReadAllBytes(path), entropy, DataProtectionScope.LocalMachine));
        }
        private static JsonElement Decode(string text) => StrictJson.Parse(new UTF8Encoding(false, true).GetString(StrictJson.Bytes(text)));
        private static byte[] Cose(JsonElement jwk, long algorithm)
        {
            bool ec = algorithm == -7;
            if (!ec && algorithm != -257)
            {
                throw StrictJson.Bad();
            }
            StrictJson.Members(jwk, ec ? new[] { "kty", "crv", "x", "y", "alg" } : new[] { "kty", "n", "e", "alg" });
            if (StrictJson.Text(jwk, "kty") != (ec ? "EC" : "RSA") || StrictJson.Text(jwk, "alg") != (ec ? "ES256" : "RS256"))
            {
                throw StrictJson.Bad();
            }
            CborWriter writer = new CborWriter();
            writer.WriteStartMap(ec ? 5 : 4);
            writer.WriteInt32(1);
            writer.WriteInt32(ec ? 2 : 3);
            writer.WriteInt32(3);
            writer.WriteInt64(algorithm);
            writer.WriteInt32(-1);
            if (ec)
            {
                if (StrictJson.Text(jwk, "crv") != "P-256")
                {
                    throw StrictJson.Bad();
                }
                byte[] x = StrictJson.Bytes(StrictJson.Text(jwk, "x"), 32), y = StrictJson.Bytes(StrictJson.Text(jwk, "y"), 32);
                if (x.Length != 32 || y.Length != 32)
                {
                    throw StrictJson.Bad();
                }
                writer.WriteInt32(1);
                writer.WriteInt32(-2);
                writer.WriteByteString(x);
                writer.WriteInt32(-3);
                writer.WriteByteString(y);
            }
            else
            {
                byte[] n = StrictJson.Bytes(StrictJson.Text(jwk, "n"), 512), e = StrictJson.Bytes(StrictJson.Text(jwk, "e"), 8);
                if (n.Length < 256)
                {
                    throw StrictJson.Bad();
                }
                writer.WriteByteString(n);
                writer.WriteInt32(-2);
                writer.WriteByteString(e);
            }
            writer.WriteEndMap();
            return writer.Encode();
        }
    }
}
