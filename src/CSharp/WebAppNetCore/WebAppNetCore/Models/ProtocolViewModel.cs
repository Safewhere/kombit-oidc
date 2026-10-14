using System.Collections.Generic;
using WebAppNetCore.OAuth;

namespace WebAppNetCore.Models
{
    /// <summary>
    /// The OAuth building blocks and the protocol state of the current sign-in, for the home page.
    /// </summary>
    public class ProtocolViewModel
    {
        /// <summary>The TempData key of the result of the last UserInfo or refresh action.</summary>
        public const string ResultKey = "ProtocolResult";

        public IList<KeyValuePair<string, string>> BuildingBlocks { get; set; }

        public IList<string> Warnings { get; set; }

        public string Result { get; set; }

        public bool IsAuthenticated { get; set; }

        /// <summary>False when the server-side state of the sign-in is gone, for example after a restart.</summary>
        public bool SessionStateAvailable { get; set; }

        public string TokenType { get; set; }

        /// <summary>The cnf.jkt claim of the access token.</summary>
        public string AccessTokenJkt { get; set; }

        /// <summary>The thumbprint of the DPoP key of the sign-in.</summary>
        public string DPoPKeyThumbprint { get; set; }

        public bool? BindingMatches => AccessTokenJkt == null || DPoPKeyThumbprint == null ? (bool?)null : AccessTokenJkt == DPoPKeyThumbprint;

        public bool HasRefreshToken { get; set; }

        public string ExpiresAt { get; set; }

        public PushedAuthorizationResult PushedAuthorization { get; set; }

        public IReadOnlyList<ProtocolTraceEntry> Trace { get; set; } = new List<ProtocolTraceEntry>();

        public string LastUserInfo { get; set; }
    }
}
