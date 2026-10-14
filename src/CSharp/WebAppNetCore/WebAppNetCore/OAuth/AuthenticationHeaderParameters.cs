using System.Text.RegularExpressions;

namespace WebAppNetCore.OAuth
{
    /// <summary>
    /// Reads one auth-param of a WWW-Authenticate challenge (RFC 9110 section 11.2), such as error="use_dpop_nonce".
    /// </summary>
    public static class AuthenticationHeaderParameters
    {
        public static string Read(string parameters, string name)
        {
            if (string.IsNullOrEmpty(parameters))
            {
                return null;
            }

            var pattern = "(?:^|,)\\s*" + Regex.Escape(name) + "\\s*=\\s*(?:\"(?<quoted>(?:[^\"\\\\]|\\\\.)*)\"|(?<token>[^\\s,]+))";
            var match = Regex.Match(parameters, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            if (!match.Success)
            {
                return null;
            }

            return match.Groups["quoted"].Success
                ? Regex.Replace(match.Groups["quoted"].Value, "\\\\(.)", "$1")
                : match.Groups["token"].Value;
        }
    }
}
