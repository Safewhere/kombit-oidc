namespace WebAppNetCore.OAuth
{
    /// <summary>
    /// The aud value of the client assertions of the sample (setting ClientAssertion:Audience).
    /// </summary>
    public enum ClientAssertionAudience
    {
        /// <summary>The URL of the token endpoint, also at the PAR endpoint. Identify accepts it when the connection has no audience rule.</summary>
        TokenEndpoint,

        /// <summary>The issuer of the discovery document as one JSON string, as the Identify rule clientAssertion.audience=issuer requires (FAPI 2.0 section 5.3.2.1 item 8).</summary>
        Issuer
    }
}
