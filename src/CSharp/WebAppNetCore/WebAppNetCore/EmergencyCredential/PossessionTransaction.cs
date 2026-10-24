using Fido2NetLib;

namespace WebAppNetCore.EmergencyCredential
{
    public sealed class PossessionTransaction
    {
        public string Id { get; set; }
        public string Purpose { get; set; }
        public string Browser { get; set; }
        public string CredentialId { get; set; }
        public string Digest { get; set; }
        public string BindingId { get; set; }
        public long Revision { get; set; }
        public long Generation { get; set; }
        public long Expires { get; set; }
        public uint Counter { get; set; }
        public string CoseKey { get; set; }
        public string UserHandle { get; set; }
        public string AuthenticatorId { get; set; }
        public AssertionOptions Options { get; set; }
    }
}
