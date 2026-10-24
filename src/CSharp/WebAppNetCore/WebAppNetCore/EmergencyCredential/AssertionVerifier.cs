using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Fido2NetLib;
using Fido2NetLib.Objects;

namespace WebAppNetCore.EmergencyCredential
{
    public sealed class AssertionVerifier
    {
        private readonly Fido2Configuration configuration;
        private readonly Fido2 fido;
        public AssertionVerifier(EmergencyOptions options)
        {
            configuration = new Fido2Configuration { RPID = options.RelyingPartyId, RPName = "OIDC sample emergency access", Origins = new HashSet<string> { options.Origin } };
            fido = new Fido2(configuration, null);
        }
        public AssertionOptions Options(string credentialId) => AssertionOptions.Create(configuration, StrictJson.Bytes(StrictJson.Id()),
            new[] { new PublicKeyCredentialDescriptor(StrictJson.Bytes(credentialId)) }, UserVerificationRequirement.Preferred, new AuthenticationExtensionsClientInputs());

        public async Task<uint> VerifyAsync(JsonElement credential, PossessionTransaction transaction, CancellationToken cancellation)
        {
            try
            {
                StrictJson.Members(credential, "id", "rawId", "type", "response", "clientExtensionResults", "authenticatorAttachment");
                if (StrictJson.Text(credential, "type") != "public-key" || StrictJson.Text(credential, "id", 2048) != transaction.AuthenticatorId
                    || StrictJson.Text(credential, "rawId", 2048) != transaction.AuthenticatorId)
                {
                    throw StrictJson.Bad();
                }
                JsonElement response = credential.GetProperty("response");
                StrictJson.Members(response, "authenticatorData", "clientDataJSON", "signature", "userHandle");
                byte[] data = StrictJson.Bytes(StrictJson.Text(response, "authenticatorData", 16384));
                if (data.Length < 37 || (data[32] & 1) == 0 || ((data[32] & 16) != 0 && (data[32] & 8) == 0))
                {
                    throw StrictJson.Bad();
                }
                JsonElement client = StrictJson.Parse(new UTF8Encoding(false, true).GetString(StrictJson.Bytes(StrictJson.Text(response, "clientDataJSON", 16384))));
                if (client.TryGetProperty("topOrigin", out _) || (client.TryGetProperty("crossOrigin", out JsonElement cross) && cross.ValueKind != JsonValueKind.False))
                {
                    throw StrictJson.Bad();
                }
                if (response.TryGetProperty("userHandle", out JsonElement user) && user.ValueKind != JsonValueKind.Null && user.GetString() != transaction.UserHandle)
                {
                    throw StrictJson.Bad();
                }
                AuthenticatorAssertionRawResponse raw = JsonSerializer.Deserialize<AuthenticatorAssertionRawResponse>(credential.GetRawText());
                await fido.MakeAssertionAsync(new MakeAssertionParams
                {
                    AssertionResponse = raw,
                    OriginalOptions = transaction.Options,
                    StoredPublicKey = StrictJson.Bytes(transaction.CoseKey),
                    StoredSignatureCounter = transaction.Counter,
                    IsUserHandleOwnerOfCredentialIdCallback = (p, token) => Task.FromResult(p.UserHandle.SequenceEqual(StrictJson.Bytes(transaction.UserHandle)) && p.CredentialId.SequenceEqual(StrictJson.Bytes(transaction.AuthenticatorId)))
                }, cancellation);
                uint counter = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(33, 4));
                if ((counter != 0 || transaction.Counter != 0) && counter <= transaction.Counter)
                {
                    throw StrictJson.Bad();
                }
                return counter;
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception) { throw new EmergencyFault(400, "assertion_rejected"); }
        }
    }
}
