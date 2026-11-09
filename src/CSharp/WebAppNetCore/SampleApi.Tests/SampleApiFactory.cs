using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace SampleApi.Tests;

/// <summary>
/// The API with the stub Identify and a client assertion certificate that the test creates.
/// </summary>
internal sealed class SampleApiFactory : WebApplicationFactory<Program>
{
    internal const string PublicBaseUrl = "https://api.test";
    internal const string ApiClientId = "fapi-test-api";

    internal SampleApiFactory()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=fapi-test-api", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        AssertionCertificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    internal StubIdentify Identify { get; } = new();

    internal X509Certificate2 AssertionCertificate { get; }

    internal async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, string? accessToken, string? proof,
        string scheme = "DPoP", HttpContent? content = null)
    {
        using var client = CreateClient();
        var request = new HttpRequestMessage(method, path) { Content = content };
        if (accessToken is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue(scheme, accessToken);
        }

        if (proof is not null)
        {
            request.Headers.Add("DPoP", proof);
        }

        return await client.SendAsync(request);
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // Not Development, so that the user secrets of a developer cannot change a test result.
        builder.UseEnvironment("Testing");
        builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["SampleApi:Issuer"] = StubIdentify.Issuer,
            ["SampleApi:Audience"] = StubIdentify.Audience,
            ["SampleApi:PublicBaseUrl"] = PublicBaseUrl,
            ["SampleApi:ClientId"] = ApiClientId,
            ["SampleApi:AssertionSigningCertPath"] = string.Empty
        }));
        builder.ConfigureTestServices(services =>
        {
            services.AddHttpClient(IdentifyMetadata.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => Identify);
            services.AddSingleton(_ => new ClientAssertionFactory(AssertionCertificate, TimeProvider.System));
        });
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            AssertionCertificate.Dispose();
        }

        base.Dispose(disposing);
    }
}
