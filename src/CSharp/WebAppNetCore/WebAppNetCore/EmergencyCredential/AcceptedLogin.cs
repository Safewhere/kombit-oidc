namespace WebAppNetCore.EmergencyCredential
{
    public sealed class AcceptedLogin
    {
        public string Id { get; set; }
        public string Browser { get; set; }
        public string Subject { get; set; }
        public string Issuer { get; set; }
        public string TokenReference { get; set; }
        public long Expires { get; set; }
        public long ForgetAfter { get; set; }
        public bool Used { get; set; }
    }
}
