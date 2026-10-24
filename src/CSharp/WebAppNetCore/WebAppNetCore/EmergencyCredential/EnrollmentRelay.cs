namespace WebAppNetCore.EmergencyCredential
{
    public sealed class EnrollmentRelay
    {
        public string Id { get; set; }
        public AcceptedLogin Login { get; set; }
        public long Expires { get; set; }
    }
}
