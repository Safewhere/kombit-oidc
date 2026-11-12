using System;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace WebAppNetCore.OAuth
{
    /// <summary>
    /// Checks the iss parameter of an authorization response (RFC 9207 section 2.4, FAPI 2.0 section 5.3.3.2 item 5).
    /// ASP.NET Core does not do this check. Identify sends iss when the System Setup rule authorize.includeIssuerInResponse is on,
    /// and then its discovery document has authorization_response_iss_parameter_supported=true.
    /// </summary>
    public static class AuthorizationResponseIssuer
    {
        /// <summary>
        /// Returns null when the response is valid, and otherwise the reason for the failure.
        /// </summary>
        public static string Validate(string iss, OpenIdConnectConfiguration metadata)
        {
            if (!string.IsNullOrEmpty(iss))
            {
                // RFC 9207 requires simple string comparison with the issuer of the metadata.
                return string.Equals(iss, metadata.Issuer, StringComparison.Ordinal)
                    ? null
                    : string.Format("The iss parameter '{0}' of the authorization response is not the issuer '{1}' (RFC 9207).", iss, metadata.Issuer);
            }

            return metadata.AuthorizationResponseIssParameterSupported
                ? "The authorization response has no iss parameter, but the discovery document has authorization_response_iss_parameter_supported=true (RFC 9207)."
                : null;
        }
    }
}
