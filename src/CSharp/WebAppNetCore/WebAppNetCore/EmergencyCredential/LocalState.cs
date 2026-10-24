using System.Collections.Generic;

namespace WebAppNetCore.EmergencyCredential
{
    public sealed class LocalState
    {
        public int Version { get; set; } = 1;
        public string SigningKeys { get; set; }
        public long Generation { get; set; }
        public string IssuerStateId { get; set; }
        public bool IssuerTrustRefreshRequired { get; set; }
        public long RevocationCursor { get; set; }
        public long LastPoll { get; set; }
        public Dictionary<string, LocalBinding> Bindings { get; set; } = new Dictionary<string, LocalBinding>();
        public Dictionary<string, RegistryEntry> Credentials { get; set; } = new Dictionary<string, RegistryEntry>();
        public Dictionary<string, LocalSession> Sessions { get; set; } = new Dictionary<string, LocalSession>();
        public HashSet<string> RemovalQueue { get; set; } = new HashSet<string>();
        public List<string> Audit { get; set; } = new List<string>();
    }
}
