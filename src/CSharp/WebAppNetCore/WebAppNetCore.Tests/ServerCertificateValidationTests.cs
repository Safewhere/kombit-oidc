using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace WebAppNetCore.Tests;

/// <summary>
/// The TLS server certificate check of the back-channel requests to Identify and to the sample resource server. Before the
/// setting Testing:AcceptAnyServerCertificate, a Debug build accepted every server certificate.
/// </summary>
public sealed class ServerCertificateValidationTests
{
    [Fact]
    public void TheHandlerValidatesTheServerCertificateByDefault()
    {
        using var handler = HttpClientHandlerProvider.Create(acceptAnyServerCertificate: false);

        Assert.Null(handler.ServerCertificateCustomValidationCallback);
    }

    [Fact]
    public void AcceptAnyServerCertificateAcceptsACertificateWithChainErrors()
    {
        using var handler = HttpClientHandlerProvider.Create(acceptAnyServerCertificate: true);

        Assert.NotNull(handler.ServerCertificateCustomValidationCallback);
        Assert.True(handler.ServerCertificateCustomValidationCallback(new HttpRequestMessage(), null, null, SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public void TheMutualTlsHandlerPresentsTheClientCertificateAndValidatesTheServerCertificate()
    {
        using var key = RSA.Create(2048);
        using var certificate = new CertificateRequest("CN=mtls-test-client", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));

        using var handler = HttpClientHandlerProvider.Create(certificate, acceptAnyServerCertificate: false);

        Assert.Null(handler.ServerCertificateCustomValidationCallback);
        Assert.Equal(ClientCertificateOption.Manual, handler.ClientCertificateOptions);
        Assert.Same(certificate, Assert.Single(handler.ClientCertificates));
    }

    [Theory]
    [InlineData(null, false)]
    [InlineData("false", false)]
    [InlineData("true", true)]
    public void AcceptAnyServerCertificateIsOffByDefault(string? value, bool expected)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Testing:AcceptAnyServerCertificate"] = value })
            .Build();

        Assert.Equal(expected, configuration.AcceptAnyServerCertificate());
    }

    [Fact]
    public void AnInvalidValueStopsTheApplication()
    {
        using var factory = new TestWebApplicationFactory(settings: new Dictionary<string, string?> { ["Testing:AcceptAnyServerCertificate"] = "yes" });

        var exception = Assert.ThrowsAny<Exception>(() => factory.CreateClient());

        Assert.Contains("'Testing:AcceptAnyServerCertificate' has the invalid value 'yes'", exception.ToString());
    }
}
