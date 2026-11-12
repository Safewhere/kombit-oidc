namespace SampleApi;

/// <summary>
/// The settings of the section SampleApi (contract section 9).
/// </summary>
public sealed class SampleApiOptions
{
    public const string SectionName = "SampleApi";

    /// <summary>The issuer of Identify. The API reads {Issuer}/.well-known/openid-configuration.</summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>The API identifier, which the access token must have in aud.</summary>
    public string Audience { get; set; } = string.Empty;

    /// <summary>The public base URL of the API. The htu claim of a DPoP proof is compared with this URL and the request path.</summary>
    public string PublicBaseUrl { get; set; } = string.Empty;

    /// <summary>The client ID of the API connection, which calls introspection.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>The PKCS #12 file with the key of the client assertion. Keep it in user secrets.</summary>
    public string AssertionSigningCertPath { get; set; } = string.Empty;

    /// <summary>The password of <see cref="AssertionSigningCertPath"/>. Keep it in user secrets.</summary>
    public string AssertionSigningCertPassword { get; set; } = string.Empty;

    /// <summary>The issuer without a trailing slash, as Identify writes it into iss.</summary>
    public string NormalizedIssuer => Issuer.TrimEnd('/');

    internal static bool IsValid(SampleApiOptions options)
    {
        return Uri.TryCreate(options.Issuer, UriKind.Absolute, out var issuer) && issuer.Scheme == Uri.UriSchemeHttps
            && !string.IsNullOrWhiteSpace(options.Audience)
            && Uri.TryCreate(options.PublicBaseUrl, UriKind.Absolute, out _)
            && !string.IsNullOrWhiteSpace(options.ClientId);
    }
}

/// <summary>
/// The scopes of the operations (contract section 4).
/// </summary>
public static class SampleApiScopes
{
    public const string Read = "sample-api.read";
    public const string Write = "sample-api.write";
}
