namespace WebAppNetCore.EmergencyCredential
{
    public sealed class LocalBinding
    {
        public string Id { get; set; }
        public string Subject { get; set; }
        public string CredentialId { get; set; }
        public string UserHandle { get; set; }
        public string CoseKey { get; set; }
        public uint Counter { get; set; }
        public long Revision { get; set; }
        public bool Blocked { get; set; }
        public long LatestActivated { get; set; }
    }
}
