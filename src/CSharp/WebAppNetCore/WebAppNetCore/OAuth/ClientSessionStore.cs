using System;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Tokens;

namespace WebAppNetCore.OAuth
{
    /// <summary>
    /// Keeps the server-side state of each sign-in in memory. The authentication properties carry only a random handle: they go
    /// into the state parameter of the authorization request and later into the cookie, so they must not hold keys.
    /// The store works for one application instance. After a restart, a session has no state, and the user signs in again.
    /// </summary>
    public sealed class ClientSessionStore
    {
        public const string HandleKey = ".client_session";
        private static readonly TimeSpan SlidingExpiration = TimeSpan.FromHours(12);

        private readonly IMemoryCache cache;

        public ClientSessionStore(IMemoryCache cache)
        {
            this.cache = cache;
        }

        /// <summary>
        /// Creates the state of a new sign-in and puts its handle in the properties. Call it before the handler protects the
        /// properties into the state parameter, that is, in OnRedirectToIdentityProvider.
        /// </summary>
        public ClientSession Create(AuthenticationProperties properties)
        {
            var session = new ClientSession(Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32)));
            properties.Items[HandleKey] = session.Handle;

            var entryOptions = new MemoryCacheEntryOptions { SlidingExpiration = SlidingExpiration };
            entryOptions.RegisterPostEvictionCallback((key, value, reason, state) => (value as IDisposable)?.Dispose());
            cache.Set(CacheKey(session.Handle), session, entryOptions);
            return session;
        }

        /// <summary>
        /// Returns the state of the sign-in of the properties, or null when the properties have no handle or the store lost it.
        /// </summary>
        public ClientSession Get(AuthenticationProperties properties)
        {
            if (properties == null || !properties.Items.TryGetValue(HandleKey, out var handle) || string.IsNullOrEmpty(handle))
            {
                return null;
            }

            return cache.TryGetValue(CacheKey(handle), out ClientSession session) ? session : null;
        }

        private static string CacheKey(string handle) => "client-session:" + handle;
    }

    /// <summary>
    /// The server-side state of one sign-in.
    /// </summary>
    public sealed class ClientSession : IDisposable
    {
        public ClientSession(string handle)
        {
            Handle = handle;
        }

        public string Handle { get; }

        /// <summary>The PAR response of the sign-in, or null when the request was not pushed.</summary>
        public PushedAuthorizationResult PushedAuthorization { get; set; }

        /// <summary>The client assertion that the PAR endpoint accepted, kept only for the fault ReplayParAssertionAtToken.</summary>
        public string PushedClientAssertion { get; set; }

        /// <summary>The DPoP key of the sign-in, or null when no DPoP setting is on.</summary>
        public DPoPKey DPoPKey { get; set; }

        public ProtocolTrace Trace { get; } = new ProtocolTrace();

        /// <summary>The fault of the sign-in (Testing:EnableFaultInjection), or None.</summary>
        public Fault SignInFault { get; set; }

        /// <summary>The claims of the last UserInfo response, as indented JSON.</summary>
        public string LastUserInfo { get; set; }

        public void Dispose()
        {
            DPoPKey?.Dispose();
        }
    }
}
