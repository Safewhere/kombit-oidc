namespace WebAppNetCore.EmergencyCredential
{
    public sealed class LocalSession
    {
        public string Id { get; set; }
        public string CredentialId { get; set; }
        public string Browser { get; set; }
        public long Generation { get; set; }
        public long Expires { get; set; }
    }
}
