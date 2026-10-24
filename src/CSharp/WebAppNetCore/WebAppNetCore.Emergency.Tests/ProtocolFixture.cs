using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using WebAppNetCore.EmergencyCredential;

namespace WebAppNetCore.Emergency.Tests
{
    public sealed class ProtocolFixture : HttpMessageHandler
    {
        public readonly string Root = Path.Combine(Path.GetTempPath(), "OidcEmergencyTests", Guid.NewGuid().ToString("N"));
        public readonly string Browser = StrictJson.Id();
        public readonly string Binding = StrictJson.Id();
        public readonly string Authenticator = StrictJson.Id();
        public readonly string Handle = StrictJson.Id();
        public readonly TestClock Clock = new TestClock();
        public EmergencyOptions Options { get; }
        public EmergencyService Service { get; private set; }
        public CredentialVerifier Verifier { get; }
        public IDataProtectionProvider Protection { get; }
        public string Trust { get; private set; }
        public bool Offline { get; set; }
        public bool FailSigningKeys { get; set; }
        public Func<Task> BeforeSigningKeysResponse { get; set; }
        public string IssuerStateId { get; set; } = StrictJson.Id();
        public long RevocationSequenceOffset { get; set; }
        public string AdditionalClaimValue { get; set; }
        public int Requests { get; private set; }
        private readonly RSA encryption = RSA.Create(2048);
        private readonly RSA rsaKey = RSA.Create(2048);
        private readonly ECDsa ecKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly ECDsa signing = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly bool elliptic;
        private readonly HttpClient http;
        private string reference;
        private readonly List<object> revocations = new List<object>();

        public ProtocolFixture(bool ec = false)
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException("These PoC tests require Windows key protection.");
            }
            elliptic = ec;
            Directory.CreateDirectory(Root);
            string unique = Guid.NewGuid().ToString("N");
            Options = new EmergencyOptions
            {
                Enabled = true,
                Origin = "https://oidc.fixture.invalid",
                RelyingPartyId = "oidc.fixture.invalid",
                Issuer = "https://issuer.fixture.invalid/emergency",
                IssuerBaseUrl = "https://issuer.fixture.invalid/runtime/",
                NormalIssuer = "https://issuer.fixture.invalid/oauth2",
                Audience = "urn:oidc:emergency:test",
                StorageDirectory = Path.Combine(Root, "state"),
                ProtectionKeysDirectory = Path.Combine(Root, "protection"),
                EncryptionPrivateKeyFile = Path.Combine(Root, "decryption.pem"),
                EncryptionKeyId = "test-encryption",
                TrustedSigningKeysFile = Path.Combine(Root, "trust.json"),
                ApiKeyEnvironmentVariable = "TEST_ISSUER_" + unique
            };
            Environment.SetEnvironmentVariable(Options.ApiKeyEnvironmentVariable, StrictJson.Id());
            File.WriteAllBytes(Options.EncryptionPrivateKeyFile, ProtectedData.Protect(Encoding.UTF8.GetBytes(encryption.ExportRSAPrivateKeyPem()), SHA256.HashData(Encoding.UTF8.GetBytes("OidcSample.Emergency.EncryptionKey.v1|" + Options.Audience)), DataProtectionScope.LocalMachine));
            ECParameters pub = signing.ExportParameters(false);
            Trust = JsonSerializer.Serialize(new
            {
                keys = new[] { new { kty = "EC", crv = "P-256", x = StrictJson.Encode(pub.Q.X), y = StrictJson.Encode(pub.Q.Y), kid = "test-signing", alg = "ES256", use = "sig" } }
            });
            File.WriteAllText(Options.TrustedSigningKeysFile, Trust);
            Protection = DataProtectionProvider.Create(new DirectoryInfo(Options.ProtectionKeysDirectory), builder => builder.SetApplicationName("OidcSampleEmergency:" + Options.Audience));
            Verifier = new CredentialVerifier(Options);
            http = new HttpClient(this, false);
            Restart();
        }
        public void RotateIssuerState()
        {
            signing.GenerateKey(ECCurve.NamedCurves.nistP256);
            ECParameters pub = signing.ExportParameters(false);
            Trust = JsonSerializer.Serialize(new
            {
                keys = new[] { new { kty = "EC", crv = "P-256", x = StrictJson.Encode(pub.Q.X), y = StrictJson.Encode(pub.Q.Y), kid = "test-signing", alg = "ES256", use = "sig" } }
            });
            IssuerStateId = StrictJson.Id();
            revocations.Clear();
        }
        public void Restart()
        {
            Service?.Dispose();
            Service = new EmergencyService(Options, new ProtectedStateStore(Options, Protection, Verifier), Verifier, new AssertionVerifier(Options), new IssuerClient(Options, http), Clock);
        }
        public string Login(string subject = "test-user") => Service.Capture(Browser, subject, Options.NormalIssuer, reference = StrictJson.Id(), Clock.Value.ToUnixTimeSeconds() + 600);
        public async Task<JsonElement> Pending(string login)
        {
            JsonElement enrollment = await Service.EnrollAsync(login, Browser, CancellationToken.None);
            return await Service.CompleteEnrollmentAsync(login, Browser, enrollment.GetProperty("enrollment_id").GetString(), JsonSerializer.SerializeToElement(new
            {
                rawId = Authenticator
            }), CancellationToken.None);
        }
        public async Task<JsonElement> Active()
        {
            string login = Login();
            JsonElement issued = await Pending(login);
            await Prove(issued, "activate", login, 1);
            return issued;
        }
        public async Task<LocalSession> Prove(JsonElement issued, string purpose, string login, uint counter)
        {
            JsonElement challenge = JsonSerializer.SerializeToElement(Service.Challenge(Browser, issued.GetProperty("emergency_credential").GetString(), purpose, login));
            return await Service.FinishAsync(Browser, challenge.GetProperty("transaction_id").GetString(), purpose, Assertion(challenge.GetProperty("publicKey"), counter), login, CancellationToken.None);
        }
        public JsonElement Assertion(JsonElement options, uint count, string mutation = "valid")
        {
            JsonObject client = new JsonObject { ["type"] = mutation == "type" ? "webauthn.create" : "webauthn.get", ["challenge"] = mutation == "challenge" ? StrictJson.Id() : options.GetProperty("challenge").GetString(), ["origin"] = mutation == "origin" ? "https://other.invalid" : Options.Origin };
            if (mutation == "crossOrigin")
                client["crossOrigin"] = true;
            if (mutation == "topOrigin")
                client["topOrigin"] = "https://other.invalid";
            byte flags = mutation == "invalid-backup-state" ? (byte)21 : mutation == "up" ? (byte)4 : mutation == "uv" ? (byte)1 : mutation == "backup" ? (byte)13 : mutation == "backedUp" ? (byte)29 : (byte)5;
            byte[] clientData = Encoding.UTF8.GetBytes(client.ToJsonString());
            byte[] data = SHA256.HashData(Encoding.UTF8.GetBytes(mutation == "rp" ? "wrong.invalid" : Options.RelyingPartyId)).Concat(new[] { flags, (byte)(count >> 24), (byte)(count >> 16), (byte)(count >> 8), (byte)count }).ToArray();
            byte[] signed = data.Concat(SHA256.HashData(clientData)).ToArray();
            byte[] signature = elliptic ? ecKey.SignData(signed, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence) : rsaKey.SignData(signed, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            if (mutation == "signature")
                signature[0] ^= 1;
            return JsonSerializer.SerializeToElement(new
            {
                id = mutation == "id" ? StrictJson.Id() : Authenticator,
                rawId = Authenticator,
                type = "public-key",
                response = new
                {
                    clientDataJSON = StrictJson.Encode(clientData),
                    authenticatorData = StrictJson.Encode(data),
                    signature = StrictJson.Encode(signature),
                    userHandle = mutation == "handle" ? StrictJson.Id() : Handle
                }
            });
        }
        public JsonElement Issue(string mutation = "valid")
        {
            long now = Clock.Value.ToUnixTimeSeconds();
            ECParameters ec = ecKey.ExportParameters(false);
            RSAParameters rsa = rsaKey.ExportParameters(false);
            object jwk = elliptic ? (object)new
            {
                kty = "EC",
                crv = "P-256",
                x = StrictJson.Encode(ec.Q.X),
                y = StrictJson.Encode(ec.Q.Y),
                alg = "ES256"
            } : new
            {
                kty = "RSA",
                n = StrictJson.Encode(rsa.Modulus),
                e = StrictJson.Encode(rsa.Exponent),
                alg = "RS256"
            };
            string id = StrictJson.Id();
            JsonObject payload = JsonSerializer.SerializeToNode(new
            {
                iss = Options.Issuer,
                aud = Options.Audience,
                sub = "test-user",
                jti = id,
                iat = now,
                nbf = now,
                exp = now + 3600,
                profile_version = CredentialVerifier.Profile,
                cnf = new
                {
                    jwk
                },
                webauthn = new
                {
                    credential_id = Authenticator,
                    rp_id = Options.RelyingPartyId,
                    origin = Options.Origin,
                    user_handle = Handle,
                    cose_alg = elliptic ? -7 : -257,
                    sign_count = 0L,
                    aaguid = Guid.Empty.ToString(),
                    hardware_policy = "poc-up"
                },
                source = new
                {
                    protocol = "oidc",
                    issuer = Options.NormalIssuer,
                    token_reference = reference ?? "synthetic-reference",
                    accepted_at = now
                },
                claims_snapshot = new[] { new { type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", value = "normal-evidence", value_type = ClaimValueTypes.String }, new { type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant", value = "normal-evidence", value_type = ClaimValueTypes.String }, new { type = "http://schemas.microsoft.com/claims/authnmethodsreferences", value = "normal-evidence", value_type = ClaimValueTypes.String }, new { type = "http://schemas.microsoft.com/claims/authnclassreference", value = "normal-evidence", value_type = ClaimValueTypes.String }, new { type = "ROLE", value = "case-admin", value_type = ClaimValueTypes.String }, new { type = "name", value = "Synthetic User", value_type = ClaimValueTypes.String }, new { type = "department", value = "A", value_type = ClaimValueTypes.String }, new { type = "department", value = "B", value_type = ClaimValueTypes.String }, new { type = "level", value = "7", value_type = ClaimValueTypes.Integer }, new { type = "email", value = "user@example.invalid", value_type = ClaimValueTypes.String }, new { type = "role", value = "read-only", value_type = ClaimValueTypes.String }, new { type = "role", value = "administrator", value_type = ClaimValueTypes.String }, new { type = "acr", value = "normal-high", value_type = ClaimValueTypes.String }, new { type = "access_token", value = "not-a-real-token", value_type = ClaimValueTypes.String }, new { type = "emergency_session_id", value = "untrusted", value_type = ClaimValueTypes.String } }
            }).AsObject();
            JsonObject header = new JsonObject { ["alg"] = "ES256", ["kid"] = "test-signing", ["typ"] = CredentialVerifier.TokenType };
            switch (mutation)
            {
                case "audience":
                    payload["aud"] = "wrong";
                    break;
                case "audience-array":
                    payload["aud"] = new JsonArray(Options.Audience);
                    break;
                case "issuer":
                    payload["iss"] = "https://wrong.invalid";
                    break;
                case "expired":
                    payload["iat"] = now - 4000;
                    payload["nbf"] = now - 4000;
                    payload["exp"] = now - 1;
                    break;
                case "long-lifetime":
                    payload["exp"] = now + 2592001;
                    break;
                case "profile":
                    payload["profile_version"] = "unknown";
                    break;
                case "source":
                    payload["source"]["issuer"] = "wrong";
                    break;
                case "rp":
                    payload["webauthn"]["rp_id"] = "wrong.invalid";
                    break;
                case "origin":
                    payload["webauthn"]["origin"] = "https://wrong.invalid";
                    break;
                case "hardware":
                    payload["webauthn"]["hardware_policy"] = "trusted-hardware";
                    break;
                case "type":
                    header["typ"] = "JWT";
                    break;
                case "unknown-key":
                    header["kid"] = "other-key";
                    break;
                case "external-key":
                    header["jku"] = "https://wrong.invalid/keys";
                    break;
                case "critical":
                    header["crit"] = new JsonArray("unknown");
                    break;
                case "none":
                    header["alg"] = "none";
                    break;
            }
            if (AdditionalClaimValue != null)
            {
                payload["claims_snapshot"].AsArray().Add(JsonSerializer.SerializeToNode(new
                {
                    type = "email",
                    value = AdditionalClaimValue,
                    value_type = ClaimValueTypes.String
                }));
            }
            string headerText = header.ToJsonString(), payloadText = payload.ToJsonString();
            if (mutation == "duplicate")
                payloadText = "{\"sub\":\"other\"," + payloadText.Substring(1);
            string input = StrictJson.Encode(Encoding.UTF8.GetBytes(headerText)) + "." + StrictJson.Encode(Encoding.UTF8.GetBytes(payloadText));
            string signed = input + "." + (mutation == "none" ? "" : StrictJson.Encode(signing.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)));
            string encrypted = new JsonWebTokenHandler().EncryptToken(signed, new EncryptingCredentials(new RsaSecurityKey(encryption) { KeyId = Options.EncryptionKeyId }, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512), new Dictionary<string, object> { ["typ"] = CredentialVerifier.TokenType });
            if (mutation == "tampered")
            {
                string[] parts = encrypted.Split('.');
                byte[] tag = StrictJson.Bytes(parts[4]);
                tag[0] ^= 1;
                parts[4] = StrictJson.Encode(tag);
                encrypted = string.Join(".", parts);
            }
            return JsonSerializer.SerializeToElement(new
            {
                ec_id = id,
                binding_id = Binding,
                emergency_credential = encrypted,
                expires_at = now + 3600,
                profile_version = CredentialVerifier.Profile
            });
        }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            if (Offline)
                throw new HttpRequestException("Synthetic offline fixture.");
            string path = request.RequestUri.AbsolutePath;
            JsonElement body = request.Content == null ? default : StrictJson.Parse(await request.Content.ReadAsStringAsync(cancellationToken));
            object result;
            if (path.EndsWith("signing-keys"))
            {
                if (FailSigningKeys)
                {
                    throw new HttpRequestException("Synthetic signing-key failure.");
                }
                string responseKeys = Trust;
                if (BeforeSigningKeysResponse != null)
                {
                    await BeforeSigningKeysResponse();
                }
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(responseKeys) };
            }
            if (request.Method == HttpMethod.Get && path.EndsWith("revocations"))
            {
                long after = long.Parse(request.RequestUri.Query.Substring("?after=".Length), System.Globalization.CultureInfo.InvariantCulture);
                var entries = revocations.Select(item => JsonSerializer.SerializeToElement(item)).Where(item => item.GetProperty("sequence").GetInt64() > after).ToArray();
                result = new
                {
                    state_id = IssuerStateId,
                    events = entries,
                    cursor = entries.Length == 0 ? after : entries.Last().GetProperty("sequence").GetInt64(),
                    has_more = false
                };
            }
            else if (path.EndsWith("revocations"))
            {
                revocations.Add(new
                {
                    sequence = RevocationSequenceOffset + (long)revocations.Count + 1,
                    kind = "binding",
                    id = body.GetProperty("binding_id").GetString(),
                    created_at = Clock.Value.ToUnixTimeSeconds()
                });
                return new HttpResponseMessage(HttpStatusCode.NoContent);
            }
            else if (request.Method == HttpMethod.Delete)
                return new HttpResponseMessage(HttpStatusCode.NoContent);
            else if (path.EndsWith("complete"))
                result = Issue();
            else
            {
                reference = body.GetProperty("normal_token_reference").GetProperty("token_reference").GetString();
                result = path.EndsWith("renewals") ? (object)Issue() : new
                {
                    enrollment_id = StrictJson.Id(),
                    expires_at = Clock.Value.ToUnixTimeSeconds() + 300,
                    publicKey = new
                    {
                        rp = new
                        {
                            id = Options.RelyingPartyId
                        }
                    }
                };
            }
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(result), Encoding.UTF8, "application/json") };
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Service.Dispose();
                http.Dispose();
                encryption.Dispose();
                rsaKey.Dispose();
                ecKey.Dispose();
                signing.Dispose();
                Environment.SetEnvironmentVariable(Options.ApiKeyEnvironmentVariable, null);
                string parent = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "OidcEmergencyTests")) + Path.DirectorySeparatorChar;
                if (Path.GetFullPath(Root).StartsWith(parent, StringComparison.OrdinalIgnoreCase))
                    Directory.Delete(Root, true);
            }
            base.Dispose(disposing);
        }
    }
}
