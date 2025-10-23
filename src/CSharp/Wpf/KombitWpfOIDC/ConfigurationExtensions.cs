using System.Configuration;
using System.Net;
using System.Net.Http;
using IdentityModel.Client;

namespace KombitWpfOIDC
{
    public static class ConfigurationExtensions
    {
        private static DiscoveryDocumentResponse? _disco;
        private static readonly HttpClient _http = new();
        public static string ClaimsIssuer => (ConfigurationManager.AppSettings["ClaimsIssuer"] ?? string.Empty).TrimEnd('/');
        public static string ClientId => ConfigurationManager.AppSettings["ClientId"] ?? string.Empty;
        public static string Port => ConfigurationManager.AppSettings["Port"] ?? string.Empty;
        public static string Scope => ConfigurationManager.AppSettings["Scope"] ?? string.Empty;
        public static string IdTokenDecryptionCertPath => ConfigurationManager.AppSettings["IdTokenDecryptionCertPath"] ?? string.Empty;
        public static string IdTokenDecryptionCertPassword => ConfigurationManager.AppSettings["IdTokenDecryptionCertPassword"] ?? string.Empty;
        public static string AuthorizationEndpointMethod => ConfigurationManager.AppSettings["AuthorizationEndpointMethod"] ?? string.Empty;

        public static async Task<DiscoveryDocumentResponse> GetDiscoveryAsync()
        {
            if (_disco != null) return _disco;
            if (string.IsNullOrWhiteSpace(ClaimsIssuer))
                throw new InvalidOperationException("ClaimsIssuer is not configured.");

            var disco = await _http.GetDiscoveryDocumentAsync(new DiscoveryDocumentRequest
            {
                Address = ClaimsIssuer,
                Policy = new DiscoveryPolicy
                {
                    RequireHttps = true,
                    ValidateEndpoints = false
                }
            }).ConfigureAwait(false);

            if (disco.IsError)
                throw new InvalidOperationException($"OIDC Discovery error: {disco.Error}");

            _disco = disco;
            return disco;
        }
        private static DiscoveryDocumentResponse RequireDisco()
        {
            if (_disco == null)
                throw new InvalidOperationException("OIDC discovery not loaded.");
            return _disco;
        }

        public static string AuthorizationEndpoint => RequireDisco().AuthorizeEndpoint;
        public static string TokenEndpoint => RequireDisco().TokenEndpoint;
        public static string EndSessionEndpoint => RequireDisco().EndSessionEndpoint;
        public static string RevokeEndpoint => RequireDisco().RevocationEndpoint;
        public static string LoopbackRedirect => string.Format("http://{0}:{1}/", IPAddress.Loopback, Port);
    }

}
