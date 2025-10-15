using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace KomitWpfOIDC
{
    public class TokenInfo
    {
        public string? IdToken { get; set; }
        public string? AccessToken { get; set; }
        public string? Header { get; set; }
        public string? Payload { get; set; }
        public DateTimeOffset AccessTokenExp { get; set; }
        public string? RefreshToken { get; set; }

        public bool HasValidAccessToken =>
            !string.IsNullOrWhiteSpace(AccessToken) &&
            AccessTokenExp > DateTimeOffset.UtcNow;

        public void Clear()
        {
            IdToken = null;
            AccessToken = null;
            RefreshToken = null;
            AccessTokenExp = default;
        }
    }
}
