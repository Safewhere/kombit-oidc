using System.Configuration;
using System.Net;

namespace KombitWpfOIDC
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
        public static string AuthorizationEndpointMethod
        {
            get => ConfigurationManager.AppSettings["AuthorizationEndpointMethod"];
        }

        public static string AuthorizationEndpoint
        {
            get => IssuerDomain + "/runtime/oauth2/authorize.idp";
        }

        public static string TokenEndpoint
        {
            get => IssuerDomain + "/runtime/oauth2/token.idp";
        }

        public static string RegistrationEndpoint
        {
            get => IssuerDomain + "/runtime/oauth2/register.idp";
        }
        public static string IntrospectionEndpoint
        {
            get => IssuerDomain + "/runtime/oauth2/introspect.idp";
        }

        public static string UserInfoEndpoint
        {
            get => IssuerDomain + "/runtime/openidconnect/userinfo.idp";
        }

        public static string EndSessionEndpoint
        {
            get => IssuerDomain + "/runtime/openidconnect/logout.idp";
        }

        public static string CheckSessionIframe
        {
            get => IssuerDomain + "/runtime/openidconnect/sessionlogout.idp";
        }

        public static string RevokeEndpoint
        {
            get => IssuerDomain + "/runtime/oauth2/revoke.idp";
        }
        public static string LoopbackRedirect => string.Format("http://{0}:{1}/", IPAddress.Loopback, Port);
    }

}
