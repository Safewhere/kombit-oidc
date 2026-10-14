using System;
using System.Linq;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using WebAppNetCore.OAuth;

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
        /// The aud value of client assertions at the token and PAR endpoints.
        /// </summary>
        public static ClientAssertionAudience ClientAssertionAudience(this IConfiguration configuration)
        {
            return ParseEnum(configuration, "OpenIdConnectOptions:ClientAssertion:Audience", OAuth.ClientAssertionAudience.TokenEndpoint);
        }

        /// <summary>
        /// The alg value of client assertions. Identify restricts it per connection with the rule clientJwt.signingAlgorithms.
        /// </summary>
        public static string ClientAssertionSigningAlgorithm(this IConfiguration configuration)
        {
            return ParseRsaSigningAlgorithm(configuration, "OpenIdConnectOptions:ClientAssertion:SigningAlgorithm", SecurityAlgorithms.RsaSha256);
        }

        /// <summary>
        /// Reads every building-block setting once, so that an invalid value stops the application at startup.
        /// </summary>
        public static void ValidateBuildingBlockSettings(this IConfiguration configuration)
        {
            configuration.ValidIdTokenSigningAlgorithms();
            configuration.ClientAssertionAudience();
            configuration.ClientAssertionSigningAlgorithm();
        }

        // The RSA algorithms that Identify accepts for client assertions and DPoP proofs.
        private static readonly string[] RsaSigningAlgorithms = { "RS256", "RS384", "RS512", "PS256", "PS384", "PS512" };

        private static string ParseRsaSigningAlgorithm(IConfiguration configuration, string key, string defaultValue)
        {
            var value = configuration[key];
            if (string.IsNullOrEmpty(value))
            {
                return defaultValue;
            }

            if (!RsaSigningAlgorithms.Contains(value, StringComparer.Ordinal))
            {
                throw InvalidSetting(key, value, string.Join(", ", RsaSigningAlgorithms));
            }

            return value;
        }

        private static TEnum ParseEnum<TEnum>(IConfiguration configuration, string key, TEnum defaultValue)
            where TEnum : struct, Enum
        {
            var value = configuration[key];
            if (string.IsNullOrEmpty(value))
            {
                return defaultValue;
            }

            // Names only: Enum.TryParse would also accept numbers.
            var name = Enum.GetNames<TEnum>().FirstOrDefault(n => string.Equals(n, value, StringComparison.OrdinalIgnoreCase));
            if (name == null)
            {
                throw InvalidSetting(key, value, string.Join(", ", Enum.GetNames<TEnum>()));
            }

            return Enum.Parse<TEnum>(name);
        }

        private static InvalidOperationException InvalidSetting(string key, string value, string allowedValues)
        {
            return new InvalidOperationException(string.Format(
                "The setting '{0}' has the invalid value '{1}'. Allowed values: {2}.", key, value, allowedValues));
        }
    }
}
