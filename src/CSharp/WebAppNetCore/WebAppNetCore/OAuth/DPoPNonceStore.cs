using System;
using System.Collections.Concurrent;
using System.Net.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace WebAppNetCore.OAuth
{
    /// <summary>
    /// The latest DPoP nonce of each server. A server can send a new nonce in any response, also in a successful one, and the
    /// client uses it in its proofs to that server until the server sends another (RFC 9449 section 8.2). The authorization
    /// server (the PAR and token endpoints) and the resource server (UserInfo) have their own nonces (RFC 9449 section 9).
    /// </summary>
    public sealed class DPoPNonceStore
    {
        private readonly ConcurrentDictionary<string, string> nonces = new ConcurrentDictionary<string, string>(StringComparer.Ordinal);

        /// <summary>The key of the authorization server: its issuer.</summary>
        public static string AuthorizationServer(OpenIdConnectConfiguration metadata) => "authorization server " + metadata.Issuer;

        /// <summary>The key of a resource server: the origin of the resource.</summary>
        public static string ResourceServer(string resourceUrl) => "resource server " + new Uri(resourceUrl).GetLeftPart(UriPartial.Authority);

        /// <summary>Returns the latest nonce of the server, or null when the server has sent none.</summary>
        public string Get(string server) => nonces.TryGetValue(server, out var nonce) ? nonce : null;

        /// <summary>Keeps the nonce of the DPoP-Nonce header when the response has one.</summary>
        public void Save(string server, HttpResponseMessage response)
        {
            var nonce = DPoPNonce.Read(response);
            if (nonce != null)
            {
                nonces[server] = nonce;
            }
        }
    }
}
