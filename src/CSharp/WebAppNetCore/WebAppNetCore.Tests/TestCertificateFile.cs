using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace WebAppNetCore.Tests;

/// <summary>
/// A self-signed RSA certificate in a temporary PFX file, for the private_key_jwt settings of the sample.
/// </summary>
internal sealed class TestCertificateFile : IDisposable
{
    internal const string Password = "test-password";

    internal TestCertificateFile()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=WebAppNetCore test client", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"webappnetcore-test-{Guid.NewGuid():N}.pfx");
        File.WriteAllBytes(Path, certificate.Export(X509ContentType.Pfx, Password));
        PublicCertificate = X509CertificateLoader.LoadCertificate(certificate.Export(X509ContentType.Cert));
    }

    internal string Path { get; }

    internal X509Certificate2 PublicCertificate { get; }

    /// <summary>The x5t#S256 value of the certificate (RFC 8705 section 3.1).</summary>
    internal string Thumbprint => WebAppNetCore.OAuth.MutualTlsClientCertificate.ComputeThumbprint(PublicCertificate);

    /// <summary>Mutual TLS with the certificate file as the TLS client certificate.</summary>
    internal IDictionary<string, string?> MutualTlsSettings(string tokenAuthnMethod = "self_signed_tls_client_auth")
    {
        return new Dictionary<string, string?>
        {
            ["OpenIdConnectOptions:TokenAuthnMethod"] = tokenAuthnMethod,
            ["OpenIdConnectOptions:MutualTls:CertificatePath"] = Path,
            ["OpenIdConnectOptions:MutualTls:CertificatePassword"] = Password
        };
    }

    internal IDictionary<string, string?> PrivateKeyJwtSettings()
    {
        return new Dictionary<string, string?>
        {
            ["OpenIdConnectOptions:TokenAuthnMethod"] = "private_key_jwt",
            ["OpenIdConnectOptions:JwtAssertionSigningCertPath"] = Path,
            ["OpenIdConnectOptions:JwtAssertionSigningCertPassword"] = Password
        };
    }

    public void Dispose()
    {
        PublicCertificate.Dispose();
        File.Delete(Path);
    }
}
