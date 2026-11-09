using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace SampleApi;

/// <summary>
/// The discovery document of Identify, with the issuer check (contract section 6 step 2).
/// </summary>
public sealed class IdentifyMetadata
{
    public const string HttpClientName = "Identify";

    private readonly ConfigurationManager<OpenIdConnectConfiguration> configurationManager;
    private readonly string issuer;

    public IdentifyMetadata(IHttpClientFactory httpClientFactory, IOptions<SampleApiOptions> options)
    {
        issuer = options.Value.NormalizedIssuer;
        var retriever = new HttpDocumentRetriever(httpClientFactory.CreateClient(HttpClientName)) { RequireHttps = true };
        configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            issuer + "/.well-known/openid-configuration", new OpenIdConnectConfigurationRetriever(), retriever);
    }

    public async Task<OpenIdConnectConfiguration> GetAsync(CancellationToken cancellationToken)
    {
        OpenIdConnectConfiguration configuration;
        try
        {
            configuration = await configurationManager.GetConfigurationAsync(cancellationToken);
        }
        catch (InvalidOperationException exception)
        {
            throw ProtectedResourceException.Unavailable("The discovery document cannot be read: " + exception.Message);
        }

        if (!string.Equals(configuration.Issuer?.TrimEnd('/'), issuer, StringComparison.Ordinal))
        {
            throw ProtectedResourceException.Unavailable("The issuer of the discovery document differs from the configured issuer.");
        }

        return configuration;
    }

    /// <summary>Reads the discovery document and the JWKS again at the next call, for example after a key rotation.</summary>
    public void RequestRefresh() => configurationManager.RequestRefresh();
}
