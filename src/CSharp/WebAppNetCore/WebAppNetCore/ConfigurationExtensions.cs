using System;
using System.Linq;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Configuration;

namespace WebAppNetCore
{
    public static class ConfigurationExtensions
    {
        public static string Scope(this IConfiguration configuration)
        {
            return configuration["OpenIdConnectOptions:Scope"];
        }

        public static string ClientId(this IConfiguration configuration)
        {
            return configuration["OpenIdConnectOptions:ClientId"];
        }

        public static string ClientSecret(this IConfiguration configuration)
        {
            return configuration["OpenIdConnectOptions:ClientSecret"];
        }

        public static string ResponseType(this IConfiguration configuration)
        {
            return configuration["OpenIdConnectOptions:ResponseType"];
        }

        public static string ResponseMode(this IConfiguration configuration)
        {
            return configuration["OpenIdConnectOptions:ResponseMode"];
        }

        public static string ClaimsIssuer(this IConfiguration configuration)
        {
            return configuration["OpenIdConnectOptions:ClaimsIssuer"].TrimEnd('/');
        }

        public static string IssuerDomain(this IConfiguration configuration)
        {
            return configuration["OpenIdConnectOptions:IssuerDomain"].TrimEnd('/');
        }

        public static string AuthorizationEndpoint(this IConfiguration configuration)
        {
            return configuration.IssuerDomain() + "/runtime/oauth2/authorize.idp";
        }

        public static string EndSessionEndpoint(this IConfiguration configuration)
        {
            return configuration.IssuerDomain() + "/runtime/openidconnect/logout.idp";
        }

        public static bool SessionManagementEnabled(this IConfiguration configuration)
        {
            return configuration.CheckSessionIframeUri() != null;
        }

        public static Uri CheckSessionIframeUri(this IConfiguration configuration)
        {
            var sessionUri = configuration["OpenIdConnectOptions:CheckSessionIframeUri"];
            if (string.IsNullOrEmpty(sessionUri))
            {
                return null;
            }
            return new Uri(sessionUri);
        }

        public static bool UsePKCE(this IConfiguration configuration)
        {
            return configuration["OpenIdConnectOptions:UsePKCE"] == "true";
        }

        public static bool RequireNonce(this IConfiguration configuration)
        {
            return bool.Parse(configuration["OpenIdConnectOptions:RequireNonce"]);
        }

        public static bool EnableSessionManagement(this IConfiguration configuration)
        {
            var enableSessionManagement = configuration["OpenIdConnectOptions:EnableSessionManagement"];
            bool.TryParse(enableSessionManagement, out bool result);
            return result;
        }

        public static bool EnablePostLogout(this IConfiguration configuration)
        {
            var enablePostLogout = configuration["OpenIdConnectOptions:EnablePostLogout"];
            bool.TryParse(enablePostLogout, out bool result);
            return result;
        }

        public static OpenIdConnectRedirectBehavior AuthorizationEndpointMethod(this IConfiguration configuration)
        {
            return configuration["OpenIdConnectOptions:AuthorizationEndpointMethod"] == "POST"? OpenIdConnectRedirectBehavior.FormPost : OpenIdConnectRedirectBehavior.RedirectGet;
        }

        public static string TokenAuthnMethod(this IConfiguration configuration)
        {
            var method = configuration["OpenIdConnectOptions:TokenAuthnMethod"];
            if (string.IsNullOrEmpty(method))
            {
                return "client_secret_post";
            }

            return method;
        }

        public static string IdTokenDecryptionCertPath(this IConfiguration configuration)
        {
            return configuration["OpenIdConnectOptions:IdTokenDecryptionCertPath"];
        }

        public static string IdTokenDecryptionCertPassword(this IConfiguration configuration)
        {
            return configuration["OpenIdConnectOptions:IdTokenDecryptionCertPassword"];
        }

        public static string JwtAssertionSigningCertPath(this IConfiguration configuration)
        {
            return configuration["OpenIdConnectOptions:JwtAssertionSigningCertPath"];
        }

        public static string JwtAssertionSigningCertPassword(this IConfiguration configuration)
        {
            return configuration["OpenIdConnectOptions:JwtAssertionSigningCertPassword"];
        }

        // The settings below are the building blocks of the US38464 plan. Each value is parsed strictly: an invalid value
        // throws, so that it never reads as "off". ValidateBuildingBlockSettings reads all of them at startup.

        private static readonly string[] AsymmetricSigningAlgorithms =
        {
            "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"
        };

        /// <summary>
        /// The allowed algorithms of the ID token signature (FAPI 2.0 section 5.4.1). Empty keeps the library default.
        /// </summary>
        public static string[] ValidIdTokenSigningAlgorithms(this IConfiguration configuration)
        {
            const string key = "OpenIdConnectOptions:ValidIdTokenSigningAlgorithms";
            var algorithms = (configuration[key] ?? string.Empty)
                .Split(new char[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var algorithm in algorithms)
            {
                if (!AsymmetricSigningAlgorithms.Contains(algorithm, StringComparer.Ordinal))
                {
                    throw InvalidSetting(key, algorithm, string.Join(", ", AsymmetricSigningAlgorithms));
                }
            }

            return algorithms;
        }

        /// <summary>
        /// Reads every building-block setting once, so that an invalid value stops the application at startup.
        /// </summary>
        public static void ValidateBuildingBlockSettings(this IConfiguration configuration)
        {
            configuration.ValidIdTokenSigningAlgorithms();
        }

        private static InvalidOperationException InvalidSetting(string key, string value, string allowedValues)
        {
            return new InvalidOperationException(string.Format(
                "The setting '{0}' has the invalid value '{1}'. Allowed values: {2}.", key, value, allowedValues));
        }
    }
}
