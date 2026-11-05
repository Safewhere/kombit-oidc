using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace WebAppNetCore.OAuth
{
    /// <summary>
    /// The TLS client certificate for mutual TLS (RFC 8705). The application loads it once, at the first request that needs it.
    /// </summary>
    public sealed class MutualTlsClientCertificate : IDisposable
    {
        private readonly Lazy<X509Certificate2> certificate;

        public MutualTlsClientCertificate(IConfiguration configuration)
        {
            certificate = new Lazy<X509Certificate2>(() => Load(configuration));
        }

        public X509Certificate2 Certificate => certificate.Value;

        /// <summary>
        /// The x5t#S256 value of the certificate (RFC 8705 section 3.1): the base64url SHA-256 hash of its DER encoding.
        /// </summary>
        public string Thumbprint => ComputeThumbprint(Certificate);

        public static string ComputeThumbprint(X509Certificate2 certificate)
        {
            return Base64UrlEncoder.Encode(SHA256.HashData(certificate.RawData));
        }

        /// <summary>
        /// Loads the certificate of MutualTls:CertificateThumbprint or MutualTls:CertificatePath. Exactly one of the two settings must
        /// have a value, and the certificate must have its private key.
        /// </summary>
        public static X509Certificate2 Load(IConfiguration configuration)
        {
            const string thumbprintKey = "OpenIdConnectOptions:MutualTls:CertificateThumbprint";
            const string pathKey = "OpenIdConnectOptions:MutualTls:CertificatePath";
            var thumbprint = configuration.MutualTlsCertificateThumbprint();
            var path = configuration.MutualTlsCertificatePath();
            if (string.IsNullOrWhiteSpace(thumbprint) == string.IsNullOrWhiteSpace(path))
            {
                throw new InvalidOperationException(string.Format(
                    "Mutual TLS needs exactly one of the settings '{0}' and '{1}'.", thumbprintKey, pathKey));
            }

            var loaded = string.IsNullOrWhiteSpace(path)
                ? FindInStore(thumbprint, thumbprintKey)
                : X509CertificateLoader.LoadPkcs12FromFile(path, configuration.MutualTlsCertificatePassword());
            if (!loaded.HasPrivateKey)
            {
                loaded.Dispose();
                throw new InvalidOperationException("The mutual TLS client certificate has no private key.");
            }

            return loaded;
        }

        public void Dispose()
        {
            if (certificate.IsValueCreated)
            {
                certificate.Value.Dispose();
            }
        }

        private static X509Certificate2 FindInStore(string thumbprint, string key)
        {
            // A thumbprint that is copied from the certificate dialog of Windows can have spaces and an invisible left-to-right mark.
            var normalized = new string(Array.FindAll(thumbprint.ToCharArray(), Uri.IsHexDigit)).ToUpperInvariant();
            var locations = OperatingSystem.IsWindows()
                ? new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine }
                : new[] { StoreLocation.CurrentUser };
            foreach (var location in locations)
            {
                using var store = new X509Store(StoreName.My, location);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                var found = store.Certificates.Find(X509FindType.FindByThumbprint, normalized, validOnly: false);
                if (found.Count > 0)
                {
                    for (var i = 1; i < found.Count; i++)
                    {
                        found[i].Dispose();
                    }

                    return found[0];
                }
            }

            throw new InvalidOperationException(string.Format(
                "The setting '{0}' has the thumbprint '{1}', but the store My of the current user{2} has no certificate with it.",
                key, normalized, OperatingSystem.IsWindows() ? " and of the local computer" : string.Empty));
        }
    }
}
