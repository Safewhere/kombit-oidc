namespace WebAppNetCore.OAuth
{
    /// <summary>
    /// The named HttpClients for the requests that the sample sends to Identify itself: PAR, token, revocation, introspection, and UserInfo.
    /// </summary>
    public static class IdentifyHttpClient
    {
        public const string Name = "Identify";

        /// <summary>
        /// The HttpClient that presents the TLS client certificate (RFC 8705). IdentifyBackChannel selects it for the requests to the
        /// mTLS endpoint aliases.
        /// </summary>
        public const string MutualTlsName = "IdentifyMutualTls";
    }
}
