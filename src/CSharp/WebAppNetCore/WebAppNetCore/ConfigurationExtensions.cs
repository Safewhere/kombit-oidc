using System;
using System.Collections.Generic;
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
        /// When the handler pushes the authorization request (RFC 9126). Disable keeps the direct authorization request.
        /// Identify always publishes require_pushed_authorization_requests=false, also for a connection that requires PAR.
        /// </summary>
        public static PushedAuthorizationBehavior PushedAuthorization(this IConfiguration configuration)
        {
            return ParseEnum(configuration, "OpenIdConnectOptions:PushedAuthorization", PushedAuthorizationBehavior.Disable);
        }

        /// <summary>
        /// Every token request (code and refresh) carries a DPoP proof, and the token response must have token_type=DPoP (RFC 9449 section 5).
        /// </summary>
        public static bool DPoPBindAccessTokens(this IConfiguration configuration)
        {
            return ParseBool(configuration, "OpenIdConnectOptions:DPoP:BindAccessTokens");
        }

        /// <summary>
        /// The authorization request, pushed or direct, carries dpop_jkt, so that Identify binds the code to the key (RFC 9449 section 10).
        /// </summary>
        public static bool DPoPSendDPoPJkt(this IConfiguration configuration)
        {
            return ParseBool(configuration, "OpenIdConnectOptions:DPoP:SendDPoPJkt");
        }

        /// <summary>
        /// The PAR request carries a DPoP proof, so that Identify binds the code to the key (RFC 9449 section 10.1). No effect on a direct request.
        /// </summary>
        public static bool DPoPSendProofToParEndpoint(this IConfiguration configuration)
        {
            return ParseBool(configuration, "OpenIdConnectOptions:DPoP:SendProofToParEndpoint");
        }

        /// <summary>
        /// The alg value of DPoP proofs. Identify restricts it per connection with the rule clientJwt.signingAlgorithms.
        /// </summary>
        public static string DPoPSigningAlgorithm(this IConfiguration configuration)
        {
            return ParseRsaSigningAlgorithm(configuration, "OpenIdConnectOptions:DPoP:SigningAlgorithm", SecurityAlgorithms.RsaSsaPssSha256);
        }

        /// <summary>
        /// Whether a sign-in needs a DPoP key. This is not a setting: each DPoP setting uses the same key of the sign-in.
        /// </summary>
        public static bool UsesDPoPKey(this IConfiguration configuration)
        {
            return configuration.DPoPBindAccessTokens() || configuration.DPoPSendDPoPJkt() || configuration.DPoPSendProofToParEndpoint();
        }

        /// <summary>
        /// Shows the fault controls on the home page, for negative tests. Never turn it on for a production client.
        /// </summary>
        public static bool EnableFaultInjection(this IConfiguration configuration)
        {
            return ParseBool(configuration, "Testing:EnableFaultInjection");
        }

        /// <summary>
        /// The client ID of another client, for the faults that authenticate as it or name it as the issuer of an assertion.
        /// The faults fail with a message when it has no value.
        /// </summary>
        public static string OtherClientId(this IConfiguration configuration)
        {
            var value = configuration["Testing:OtherClientId"];
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new OAuthClientException("The fault needs the client ID of another client in Testing:OtherClientId.");
            }

            return value;
        }

        /// <summary>
        /// Reads every building-block setting once, so that an invalid value stops the application at startup.
        /// </summary>
        public static void ValidateBuildingBlockSettings(this IConfiguration configuration)
        {
            configuration.EnableFaultInjection();
            configuration.ValidIdTokenSigningAlgorithms();
            configuration.ClientAssertionAudience();
            configuration.ClientAssertionSigningAlgorithm();
            configuration.PushedAuthorization();
            configuration.DPoPBindAccessTokens();
            configuration.DPoPSendDPoPJkt();
            configuration.DPoPSendProofToParEndpoint();
            configuration.DPoPSigningAlgorithm();
        }

        /// <summary>
        /// The active building blocks, for the startup log and the home page.
        /// </summary>
        public static IList<KeyValuePair<string, string>> DescribeBuildingBlocks(this IConfiguration configuration)
        {
            var blocks = new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("Client authentication (TokenAuthnMethod)", configuration.TokenAuthnMethod())
            };
            if (configuration.TokenAuthnMethod() == "private_key_jwt")
            {
                blocks.Add(new KeyValuePair<string, string>("Client assertion", string.Format(
                    "aud={0}, alg={1}", configuration.ClientAssertionAudience(), configuration.ClientAssertionSigningAlgorithm())));
            }

            blocks.Add(new KeyValuePair<string, string>("Pushed authorization requests (PushedAuthorization)", configuration.PushedAuthorization().ToString()));
            blocks.Add(new KeyValuePair<string, string>("DPoP-bound access tokens (DPoP:BindAccessTokens)", configuration.DPoPBindAccessTokens().ToString()));
            blocks.Add(new KeyValuePair<string, string>("DPoP code binding with dpop_jkt (DPoP:SendDPoPJkt)", configuration.DPoPSendDPoPJkt().ToString()));
            blocks.Add(new KeyValuePair<string, string>("DPoP proof at PAR (DPoP:SendProofToParEndpoint)", configuration.DPoPSendProofToParEndpoint().ToString()));
            if (configuration.UsesDPoPKey())
            {
                blocks.Add(new KeyValuePair<string, string>("DPoP proof algorithm (DPoP:SigningAlgorithm)", configuration.DPoPSigningAlgorithm()));
            }

            var algorithms = configuration.ValidIdTokenSigningAlgorithms();
            blocks.Add(new KeyValuePair<string, string>("ID token algorithms (ValidIdTokenSigningAlgorithms)",
                algorithms.Length == 0 ? "library default" : string.Join(", ", algorithms)));
            if (configuration.EnableFaultInjection())
            {
                blocks.Add(new KeyValuePair<string, string>("Fault injection (Testing:EnableFaultInjection)", "True"));
            }

            return blocks;
        }

        /// <summary>
        /// Combinations that cannot succeed and that the sample can detect alone. The sample still sends what the settings say, so
        /// that the response of Identify is visible.
        /// </summary>
        public static IList<string> BuildingBlockWarnings(this IConfiguration configuration)
        {
            var warnings = new List<string>();
            var codeIsBound = configuration.DPoPSendDPoPJkt()
                || (configuration.DPoPSendProofToParEndpoint() && configuration.PushedAuthorization() != PushedAuthorizationBehavior.Disable);
            if (codeIsBound && !configuration.DPoPBindAccessTokens())
            {
                warnings.Add("The authorization code is bound to the DPoP key (DPoP:SendDPoPJkt or DPoP:SendProofToParEndpoint), but DPoP:BindAccessTokens is false. "
                    + "The token request has no proof, so Identify rejects the code redemption.");
            }

            if (configuration.DPoPSendProofToParEndpoint() && configuration.PushedAuthorization() == PushedAuthorizationBehavior.Disable)
            {
                warnings.Add("DPoP:SendProofToParEndpoint has no effect, because PushedAuthorization is Disable.");
            }

            if (configuration.EnableSessionManagement() && configuration.PushedAuthorization() != PushedAuthorizationBehavior.Disable)
            {
                warnings.Add("EnableSessionManagement sends a direct authorization request from the session check iframe. "
                    + "It fails when the Identify connection has RequirePushedAuthorizationRequests=true.");
            }

            return warnings;
        }

        private static bool ParseBool(IConfiguration configuration, string key)
        {
            var value = configuration[key];
            if (string.IsNullOrEmpty(value))
            {
                return false;
            }

            if (!bool.TryParse(value, out var result))
            {
                throw InvalidSetting(key, value, "true, false");
            }

            return result;
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
