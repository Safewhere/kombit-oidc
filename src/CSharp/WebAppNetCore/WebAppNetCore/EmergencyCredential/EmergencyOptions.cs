using System;
using System.IO;
using System.Linq;

namespace WebAppNetCore.EmergencyCredential
{
    public sealed class EmergencyOptions
    {
        public bool Enabled { get; set; }
        public string Origin { get; set; } = "";
        public string RelyingPartyId { get; set; } = "";
        public string Issuer { get; set; } = "";
        public string IssuerBaseUrl { get; set; } = "";
        public string NormalIssuer { get; set; } = "";
        public string Audience { get; set; } = "";
        public string StorageDirectory { get; set; } = "";
        public string ProtectionKeysDirectory { get; set; } = "";
        public string EncryptionPrivateKeyFile { get; set; } = "";
        public string EncryptionKeyId { get; set; } = "";
        public string TrustedSigningKeysFile { get; set; } = "";
        public string ApiKey { get; set; }
        public string BackendKey()
        {
            if (ApiKey == null) return Secret(ApiKeyEnvironmentVariable);
            if (string.IsNullOrWhiteSpace(ApiKey) || ApiKey.Length > 512 || ApiKey.Any(char.IsControl)) throw new InvalidOperationException("Invalid configured API key.");
            return ApiKey;
        }
        public string ApiKeyEnvironmentVariable { get; set; } = "OIDC_EMERGENCY_ISSUER_KEY";
        public int SessionMinutes { get; set; } = 480;

        public void Validate(string applicationRoot)
        {
            if (!Enabled)
            {
                return;
            }
            if (!Uri.TryCreate(Origin, UriKind.Absolute, out Uri origin) || origin.Scheme != "https"
                || Origin != origin.GetLeftPart(UriPartial.Authority) || origin.UserInfo.Length != 0
                || origin.Host != RelyingPartyId || !Https(Issuer) || !Https(IssuerBaseUrl)
                || !IssuerBaseUrl.EndsWith("/", StringComparison.Ordinal) || string.IsNullOrWhiteSpace(NormalIssuer)
                || string.IsNullOrWhiteSpace(Audience) || string.IsNullOrWhiteSpace(EncryptionKeyId)
                || SessionMinutes < 1 || SessionMinutes > 480)
            {
                throw new InvalidOperationException("Invalid emergency configuration.");
            }
            foreach (string path in new[] { StorageDirectory, ProtectionKeysDirectory, EncryptionPrivateKeyFile, TrustedSigningKeysFile })
            {
                ExternalPath(path, applicationRoot);
            }
            if (string.Equals(Path.GetFullPath(StorageDirectory), Path.GetFullPath(ProtectionKeysDirectory), StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Use a separate protection key directory.");
            }
            BackendKey();
        }

        public static string Secret(string name)
        {
            string value = Environment.GetEnvironmentVariable(name);
            if (value == null || value.Length < 32 || value.Length > 512 || value.Any(char.IsControl))
            {
                throw new InvalidOperationException("Emergency secret is unavailable.");
            }
            return value;
        }

        public static void ExternalPath(string path, string applicationRoot)
        {
            if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) || path.StartsWith(@"\\", StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Emergency storage must use an external local path.");
            }
            string full = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            string root = Path.GetFullPath(applicationRoot).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            if (full.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Emergency storage must be outside the application.");
            }
            for (DirectoryInfo directory = new DirectoryInfo(Path.GetFullPath(path)); directory != null; directory = directory.Parent)
            {
                if (Directory.Exists(Path.Combine(directory.FullName, ".git")) || File.Exists(Path.Combine(directory.FullName, ".git")))
                {
                    throw new InvalidOperationException("Emergency storage must be outside source repositories.");
                }
            }
        }

        private static bool Https(string value) => Uri.TryCreate(value, UriKind.Absolute, out Uri uri)
            && uri.Scheme == "https" && uri.UserInfo.Length == 0 && uri.Fragment.Length == 0 && uri.Query.Length == 0;
    }
}
