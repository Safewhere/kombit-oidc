using System.Collections.Generic;

namespace WebAppNetCore.EmergencyCredential
{
    public sealed class VerifiedCredential
    {
        public string Id { get; set; }
        public string Subject { get; set; }
        public string SourceIssuer { get; set; }
        public string SourceReference { get; set; }
        public long Issued { get; set; }
        public long Expires { get; set; }
        public string CredentialId { get; set; }
        public string UserHandle { get; set; }
        public string CoseKey { get; set; }
        public uint Counter { get; set; }
        public string Digest { get; set; }
        public List<SnapshotClaim> Claims { get; set; } = new List<SnapshotClaim>();
    }
}
