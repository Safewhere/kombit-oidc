using System;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

namespace WebAppNetCore.OAuth
{
    /// <summary>
    /// Checks that the ID token is signed. For the ID token of the token endpoint, ASP.NET Core sets
    /// TokenValidationParameters.RequireSignedTokens to false (OpenID Connect Core section 3.1.3.7), and ValidAlgorithms applies
    /// only to a signed token. Without this check, an ID token with alg "none" passes the validation of the handler.
    /// </summary>
    public static class IdTokenSignature
    {
        /// <summary>
        /// Returns null when the ID token is signed, and otherwise the reason for the failure.
        /// </summary>
        public static string Validate(JwtSecurityToken idToken)
        {
            ArgumentNullException.ThrowIfNull(idToken);
            if (!string.IsNullOrEmpty(idToken.RawSignature)
                && !string.Equals(idToken.Header.Alg, SecurityAlgorithms.None, StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            return string.Format("The ID token is not signed (alg '{0}'). The sample accepts only a signed ID token.", idToken.Header.Alg);
        }
    }
}
