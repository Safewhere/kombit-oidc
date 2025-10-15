using System.Configuration;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace KomitWpfOIDC
{
    public static class ConfigurationExtensions
    {
        public static string IssuerDomain
        {
            get => ConfigurationManager.AppSettings["IssuerDomain"].TrimEnd('/');
        }

        public static string ClaimsIssuer
        {
            get => ConfigurationManager.AppSettings["ClaimsIssuer"];
        }

        public static string ClientId
        {
            get => ConfigurationManager.AppSettings["ClientId"];
        }

        public static string ClientSecret
        {
            get => ConfigurationManager.AppSettings["ClientSecret"];
        }

        public static string ResourceUri
        {
            get => ConfigurationManager.AppSettings["ResourceUri"];
        }

        public static Uri RedirectUri
        {
            get => new Uri(ConfigurationManager.AppSettings["RedirectUri"]);
        }

        public static string Port
        {
            get => ConfigurationManager.AppSettings["Port"];
        }

        public static string Scope
        {
            get => ConfigurationManager.AppSettings["Scope"];
        }
        public static string IdTokenDecryptionCertPath
        {
            get => ConfigurationManager.AppSettings["IdTokenDecryptionCertPath"];
        }

        public static string IdTokenDecryptionCertPassword
        {
            get => ConfigurationManager.AppSettings["IdTokenDecryptionCertPassword"];
        }

        public static string AuthorizationEndpoint
        {
            get => IssuerDomain + "/runtime/oauth2/authorize.idp";
        }

        public static string TokenEndpoint
        {
            get => IssuerDomain + "/runtime/oauth2/token.idp";
        }

        public static string UserInfoEndpoint
        {
            get => IssuerDomain + "/runtime/openidconnect/userinfo.idp";
        }

        public static string EndSessionEndpoint
        {
            get => IssuerDomain + "/runtime/openidconnect/logout.idp";
        }
        public static string RevokeEndpoint
        {
            get => IssuerDomain + "/runtime/oauth2/revoke.idp";
        }

        public static X509Certificate2 IssuerSigningKey
        {
            get => new X509Certificate2(Convert.FromBase64String(ConfigurationManager.AppSettings["IssuerSigningKey"]));
        }
        public static string LoopbackRedirect => string.Format("http://{0}:{1}/", IPAddress.Loopback, Port);
    }

}
