using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace WebAppNetCore.EmergencyCredential
{
    public sealed class EmergencyService : IDisposable
    {
        public const string AuthenticationType = "OidcSampleEmergency";
        private readonly EmergencyOptions options;
        private readonly ProtectedStateStore store;
        private readonly CredentialVerifier credentials;
        private readonly AssertionVerifier assertions;
        private readonly IssuerClient issuer;
        private readonly TimeProvider clock;
        private readonly Dictionary<string, AcceptedLogin> logins = new Dictionary<string, AcceptedLogin>();
        private readonly Dictionary<string, EnrollmentRelay> enrollments = new Dictionary<string, EnrollmentRelay>();
        private readonly Dictionary<string, PossessionTransaction> challenges = new Dictionary<string, PossessionTransaction>();
        private readonly Dictionary<string, Queue<long>> rates = new Dictionary<string, Queue<long>>();
        public EmergencyService(EmergencyOptions configuration, ProtectedStateStore state, CredentialVerifier verifier, AssertionVerifier assertionVerifier, IssuerClient backend, TimeProvider time)
        {
            options = configuration;
            store = state;
            credentials = verifier;
            assertions = assertionVerifier;
            issuer = backend;
            clock = time;
        }
        private long Now => clock.GetUtcNow().ToUnixTimeSeconds();

        public string Capture(string browser, string subject, string normalIssuer, string reference, long expires)
        {
            if (normalIssuer != options.NormalIssuer || string.IsNullOrEmpty(subject) || subject.Length > 1024
                || string.IsNullOrEmpty(reference) || reference.Length > 1024 || expires <= Now)
            {
                throw new EmergencyFault(403, "normal_login_not_eligible");
            }
            lock (store.Gate)
            {
                Cleanup();
                if (logins.Count >= 2000)
                {
                    throw new EmergencyFault(503, "login_capacity");
                }
                AcceptedLogin login = new AcceptedLogin { Id = StrictJson.Id(), Browser = browser, Subject = subject, Issuer = normalIssuer, TokenReference = reference, Expires = Math.Min(expires, Now + 86400), ForgetAfter = Now + 172800 };
                logins.Add(login.Id, login);
                return login.Id;
            }
        }

        public bool HasLogin(string loginId, string browser)
        {
            lock (store.Gate)
            {
                return loginId != null && logins.TryGetValue(loginId, out AcceptedLogin login) && login.Browser == browser && login.Expires > Now && !login.Used;
            }
        }
        private AcceptedLogin Login(string loginId, string browser, bool consume)
        {
            if (loginId == null || !logins.TryGetValue(loginId, out AcceptedLogin login) || login.Browser != browser || login.ForgetAfter <= Now || (consume && (login.Used || login.Expires <= Now)))
            {
                throw new EmergencyFault(409, "new_normal_login_required");
            }
            if (consume)
            {
                login.Used = true;
            }
            return login;
        }
        private static object Reference(AcceptedLogin login) => new { protocol = "oidc", issuer = login.Issuer, token_reference = login.TokenReference };

        public async Task<JsonElement> EnrollAsync(string loginId, string browser, CancellationToken cancellation)
        {
            lock (store.Gate)
            {
                Login(loginId, browser, false);
            }
            await SynchronizeIssuerAsync(cancellation);
            AcceptedLogin login;
            lock (store.Gate)
            {
                Cleanup();
                if (enrollments.Count >= 1000)
                {
                    throw new EmergencyFault(503, "enrollment_capacity");
                }
                login = Login(loginId, browser, true);
            }
            JsonElement response = await issuer.SendAsync(HttpMethod.Post, "emergency/enrollments", new
            {
                normal_token_reference = Reference(login)
            }, cancellation);
            string id = StrictJson.Text(response, "enrollment_id", 128);
            JsonElement creation = response.GetProperty("publicKey");
            if (StrictJson.Text(creation.GetProperty("rp"), "id") != options.RelyingPartyId)
            {
                throw new EmergencyFault(502, "issuer_response_rejected");
            }
            lock (store.Gate)
            {
                enrollments.Add(id, new EnrollmentRelay { Id = id, Login = login, Expires = Math.Min(login.Expires, StrictJson.Integer(response, "expires_at")) });
            }
            return response;
        }
        public async Task<JsonElement> CompleteEnrollmentAsync(string loginId, string browser, string id, JsonElement credential, CancellationToken cancellation)
        {
            EnrollmentRelay enrollment;
            long generation;
            lock (store.Gate)
            {
                AcceptedLogin login = Login(loginId, browser, false);
                if (!enrollments.TryGetValue(id, out enrollment) || enrollment.Expires <= Now || enrollment.Login.Id != login.Id)
                {
                    throw new EmergencyFault(410, "enrollment_expired");
                }
                enrollments.Remove(id);
                generation = store.Read(state => state.Generation);
            }
            string expectedId = StrictJson.Text(credential, "rawId", 2048);
            JsonElement response = await issuer.SendAsync(HttpMethod.Post, "emergency/enrollments/" + Uri.EscapeDataString(id) + "/complete", new
            {
                credential
            }, cancellation);
            return AddPending(response, enrollment.Login, null, expectedId, generation);
        }
        public async Task CancelAsync(string loginId, string browser, string id, CancellationToken cancellation)
        {
            lock (store.Gate)
            {
                AcceptedLogin login = Login(loginId, browser, false);
                if (!enrollments.TryGetValue(id, out EnrollmentRelay enrollment) || enrollment.Login.Id != login.Id)
                {
                    throw new EmergencyFault(404, "enrollment_not_found");
                }
                enrollments.Remove(id);
            }
            await issuer.SendAsync(HttpMethod.Delete, "emergency/enrollments/" + Uri.EscapeDataString(id), null, cancellation);
        }
        public async Task<JsonElement> RenewAsync(string loginId, string browser, string bindingId, CancellationToken cancellation)
        {
            lock (store.Gate)
            {
                Login(loginId, browser, false);
            }
            await SynchronizeIssuerAsync(cancellation);
            AcceptedLogin login;
            long generation;
            lock (store.Gate)
            {
                login = Login(loginId, browser, false);
                store.Read(state => OwnedBinding(state, bindingId, login.Subject));
                Login(loginId, browser, true);
                generation = store.Read(state => state.Generation);
            }
            JsonElement response = await issuer.SendAsync(HttpMethod.Post, "emergency/renewals", new
            {
                normal_token_reference = Reference(login),
                binding_id = bindingId
            }, cancellation);
            return AddPending(response, login, bindingId, null, generation);
        }
        private JsonElement AddPending(JsonElement response, AcceptedLogin login, string expectedBinding, string expectedCredential, long generation)
        {
            string compact = StrictJson.Text(response, "emergency_credential", 65536);
            string bindingId = StrictJson.Text(response, "binding_id", 128);
            VerifiedCredential verified = credentials.Verify(compact, store.Read(state => state.SigningKeys), clock.GetUtcNow());
            if (verified.Subject != login.Subject || verified.SourceIssuer != login.Issuer || verified.SourceReference != login.TokenReference
                || StrictJson.Text(response, "ec_id", 128) != verified.Id || StrictJson.Integer(response, "expires_at") != verified.Expires
                || StrictJson.Text(response, "profile_version") != CredentialVerifier.Profile
                || (expectedBinding != null && expectedBinding != bindingId) || (expectedCredential != null && expectedCredential != verified.CredentialId))
            {
                throw new EmergencyFault(400, "issued_credential_mismatch");
            }
            store.Update(state =>
            {
                if (state.Generation != generation)
                {
                    throw new EmergencyFault(409, "synchronization_changed");
                }
                if (state.Credentials.Count >= 10000)
                {
                    throw new EmergencyFault(403, "local_policy_denied");
                }
                if (state.Bindings.TryGetValue(bindingId, out LocalBinding existing))
                {
                    if (existing.Subject != verified.Subject || existing.CredentialId != verified.CredentialId || existing.CoseKey != verified.CoseKey || existing.UserHandle != verified.UserHandle || existing.Blocked)
                    {
                        throw new EmergencyFault(403, "binding_mismatch");
                    }
                }
                else
                {
                    if (expectedBinding != null || state.Bindings.Count >= 10000 || state.Bindings.Values.Any(binding => binding.CredentialId == verified.CredentialId))
                    {
                        throw new EmergencyFault(409, "binding_conflict");
                    }
                    state.Bindings.Add(bindingId, new LocalBinding { Id = bindingId, Subject = verified.Subject, CredentialId = verified.CredentialId, UserHandle = verified.UserHandle, CoseKey = verified.CoseKey, Counter = verified.Counter });
                }
                state.Credentials.Add(verified.Id, new RegistryEntry { BindingId = bindingId, Credential = verified });
                Audit(state, "credential_pending");
                return true;
            });
            return response;
        }

        // Read-only local eligibility: no issuer call, challenge, or session is created.
        public bool IsActiveForLogin(string compact)
        {
            try
            {
                VerifiedCredential credential = credentials.Verify(compact, store.Read(state => state.SigningKeys), clock.GetUtcNow());
                lock (store.Gate)
                {
                    return store.Read(state => Entry(state, credential.Id, "active").Credential.Digest == credential.Digest);
                }
            }
            catch (EmergencyFault) { return false; }
        }

        public object Challenge(string browser, string compact, string purpose, string loginId)
        {
            VerifiedCredential credential = credentials.Verify(compact, store.Read(state => state.SigningKeys), clock.GetUtcNow());
            lock (store.Gate)
            {
                Cleanup();
                if (challenges.Count >= 1000)
                {
                    throw new EmergencyFault(503, "challenge_capacity");
                }
                return store.Read(state =>
                {
                    RegistryEntry entry = Entry(state, credential.Id, purpose == "login" ? "active" : "pending");
                    if (entry.Credential.Digest != credential.Digest)
                    {
                        throw new EmergencyFault(403, "credential_not_registered");
                    }
                    if (purpose == "activate")
                    {
                        if (Login(loginId, browser, false).Subject != credential.Subject)
                        {
                            throw new EmergencyFault(403, "account_mismatch");
                        }
                    }
                    else if (purpose != "login")
                    {
                        throw StrictJson.Bad();
                    }
                    LocalBinding binding = state.Bindings[entry.BindingId];
                    PossessionTransaction transaction = new PossessionTransaction
                    {
                        Id = StrictJson.Id(),
                        Purpose = purpose,
                        Browser = browser,
                        CredentialId = credential.Id,
                        Digest = credential.Digest,
                        BindingId = entry.BindingId,
                        Revision = binding.Revision,
                        Generation = state.Generation,
                        Counter = binding.Counter,
                        Expires = Math.Min(Now + 120, credential.Expires),
                        CoseKey = binding.CoseKey,
                        UserHandle = binding.UserHandle,
                        AuthenticatorId = binding.CredentialId,
                        Options = assertions.Options(binding.CredentialId)
                    };
                    challenges.Add(transaction.Id, transaction);
                    return new
                    {
                        transaction_id = transaction.Id,
                        publicKey = transaction.Options,
                        expires_at = transaction.Expires
                    };
                });
            }
        }
        public async Task<LocalSession> FinishAsync(string browser, string id, string purpose, JsonElement credential, string loginId, CancellationToken cancellation)
        {
            PossessionTransaction transaction;
            lock (store.Gate)
            {
                if (!challenges.TryGetValue(id, out transaction) || transaction.Browser != browser || transaction.Purpose != purpose)
                {
                    throw new EmergencyFault(410, "challenge_unavailable");
                }
                challenges.Remove(id);
                if (transaction.Expires <= Now)
                {
                    throw new EmergencyFault(410, "challenge_expired");
                }
            }
            uint counter = await assertions.VerifyAsync(credential, transaction, cancellation);
            lock (store.Gate)
            {
                return store.Update(state =>
                {
                    RegistryEntry entry = Entry(state, transaction.CredentialId, purpose == "login" ? "active" : "pending");
                    LocalBinding binding = state.Bindings[entry.BindingId];
                    if (transaction.Expires <= Now || binding.Revision != transaction.Revision || binding.Counter != transaction.Counter
                        || entry.Credential.Digest != transaction.Digest || state.Generation != transaction.Generation)
                    {
                        throw new EmergencyFault(409, "state_changed_retry");
                    }
                    if (purpose == "activate")
                    {
                        if (Login(loginId, browser, false).Subject != entry.Credential.Subject || entry.Credential.Issued <= binding.LatestActivated)
                        {
                            throw new EmergencyFault(409, "replacement_superseded");
                        }
                        foreach (RegistryEntry old in state.Credentials.Values.Where(item => item.BindingId == entry.BindingId && item.Status == "active"))
                        {
                            old.Status = "replaced";
                        }
                        entry.Status = "active";
                        binding.LatestActivated = entry.Credential.Issued;
                        binding.Counter = counter;
                        binding.Revision++;
                        Audit(state, "credential_activated");
                        return null;
                    }
                    foreach (string expired in state.Sessions.Where(pair => pair.Value.Expires <= Now).Select(pair => pair.Key).ToArray())
                    {
                        state.Sessions.Remove(expired);
                    }
                    if (state.Sessions.Count >= 2000)
                    {
                        throw new EmergencyFault(503, "session_capacity");
                    }
                    binding.Counter = counter;
                    binding.Revision++;
                    LocalSession session = new LocalSession { Id = StrictJson.Id(), CredentialId = entry.Credential.Id, Browser = browser, Generation = state.Generation, Expires = Math.Min(Now + options.SessionMinutes * 60, entry.Credential.Expires) };
                    state.Sessions.Add(session.Id, session);
                    Audit(state, "session_created");
                    return session;
                });
            }
        }

        private RegistryEntry Entry(LocalState state, string id, string status)
        {
            if (!state.Credentials.TryGetValue(id, out RegistryEntry entry) || entry.Status != status || entry.Credential.Expires <= Now
                || !state.Bindings.TryGetValue(entry.BindingId, out LocalBinding binding) || binding.Blocked)
            {
                throw new EmergencyFault(403, "credential_unavailable");
            }
            return entry;
        }
        private static LocalBinding OwnedBinding(LocalState state, string id, string subject)
        {
            if (!state.Bindings.TryGetValue(id, out LocalBinding binding) || binding.Subject != subject)
            {
                throw new EmergencyFault(404, "binding_not_found");
            }
            if (binding.Blocked)
            {
                throw new EmergencyFault(403, "binding_blocked");
            }
            return binding;
        }
        public ClaimsPrincipal Session(string id, string browser)
        {
            if (id == null)
            {
                return null;
            }
            return store.Read(state =>
            {
                if (!state.Sessions.TryGetValue(id, out LocalSession session) || session.Browser != browser || session.Expires <= Now || session.Generation != state.Generation)
                {
                    return null;
                }
                RegistryEntry entry;
                try
                {
                    entry = Entry(state, session.CredentialId, "active");
                }
                catch (EmergencyFault) { return null; }
                ClaimsIdentity identity = new ClaimsIdentity(AuthenticationType, "emergency_display", "role");
                identity.AddClaim(new Claim("emergency_display", "Prepared user"));
                identity.AddClaim(new Claim("emergency_session_id", session.Id));
                identity.AddClaim(new Claim("emergency_expires", session.Expires.ToString(System.Globalization.CultureInfo.InvariantCulture)));
                identity.AddClaim(new Claim("emergency", "true"));
                identity.AddClaim(new Claim("local_assurance", "emergency-possession"));
                // Original normal-login claims are retained as historical snapshot data.
                foreach (SnapshotClaim claim in entry.Credential.Claims)
                {
                    // Source tokens cannot replace locally generated emergency controls.
                    if (claim.Type.StartsWith("emergency", StringComparison.OrdinalIgnoreCase) || claim.Type.StartsWith("local_", StringComparison.OrdinalIgnoreCase)) { continue; }

                    identity.AddClaim(new Claim(claim.Type, claim.Value, claim.ValueType));
                }
                string display = identity.FindFirst("name")?.Value ?? identity.FindFirst(ClaimTypes.Name)?.Value;
                if (!string.IsNullOrWhiteSpace(display))
                {
                    identity.RemoveClaim(identity.FindFirst("emergency_display"));
                    identity.AddClaim(new Claim("emergency_display", display));
                }
                return new ClaimsPrincipal(identity);
            });
        }
        internal static bool Reserved(string type)
        {
            string lower = type.ToLowerInvariant();
            return lower.StartsWith("emergency", StringComparison.Ordinal) || lower.StartsWith("local_", StringComparison.Ordinal)
                || new[] { "client_id", "azp", "scope", "scp", "cnf", "act", "may_act", "token_usage", "confidentiality_level", "nonce", "at_hash", "c_hash", "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant", "http://schemas.microsoft.com/claims/authnmethodsreferences", "http://schemas.microsoft.com/claims/authnclassreference", "acr", "amr", "sid", "sub", "iss", "aud", "jti", "iat", "nbf", "exp", "auth_time", "session_state" }.Contains(lower)
                || lower.Contains("token") || lower.Contains("bootstrap") || lower.Contains("assurance") || lower.Contains("/loa") || lower.Contains("privilege");
        }
        public void SignOut(string id)
        {
            if (id == null)
            {
                return;
            }
            store.Update(state => state.Sessions.Remove(id));
        }
        public object Status(string loginId, string browser)
        {
            lock (store.Gate)
            {
                AcceptedLogin login = Login(loginId, browser, false);
                return store.Read(state => new
                {
                    can_prepare = !login.Used && login.Expires > Now,
                    credentials = state.Credentials.Values.Where(entry => entry.Credential.Subject == login.Subject).Select(entry => new
                    {
                        ec_id = entry.Credential.Id,
                        binding_id = entry.BindingId,
                        status = state.Bindings[entry.BindingId].Blocked ? "blocked" : entry.Credential.Expires <= Now ? "expired" : entry.Status,
                        expires_at = entry.Credential.Expires,
                        renew_soon = entry.Credential.Expires < Now + 3 * 86400
                    }).ToArray()
                });
            }
        }
        public async Task RemoveAsync(string loginId, string browser, string bindingId, CancellationToken cancellation)
        {
            lock (store.Gate)
            {
                AcceptedLogin login = Login(loginId, browser, false);
                store.Update(state =>
                {
                    if (!state.Bindings.TryGetValue(bindingId, out LocalBinding binding) || binding.Subject != login.Subject)
                    {
                        throw new EmergencyFault(404, "binding_not_found");
                    }
                    Block(state, bindingId);
                    foreach (string credentialId in state.Credentials.Where(pair => pair.Value.BindingId == bindingId).Select(pair => pair.Key).ToArray())
                    {
                        state.Credentials.Remove(credentialId);
                    }
                    state.Bindings.Remove(bindingId);
                    state.RemovalQueue.Add(bindingId);
                    Audit(state, "key_removed");
                    return true;
                });
            }
            // Local deletion is durable even when the issuer is unavailable; only its revocation ID is queued.
            try
            {
                await ReportRemovalAsync(bindingId, cancellation);
            }
            catch (Exception exception) when (!(exception is OperationCanceledException)) { }
        }
        private static void Block(LocalState state, string id)
        {
            if (state.Bindings.TryGetValue(id, out LocalBinding binding))
            {
                binding.Blocked = true;
                binding.Revision++;
            }
            foreach (RegistryEntry entry in state.Credentials.Values.Where(entry => entry.BindingId == id))
            {
                entry.Status = "blocked";
            }
            foreach (string session in state.Sessions.Where(pair => state.Credentials[pair.Value.CredentialId].BindingId == id).Select(pair => pair.Key).ToArray())
            {
                state.Sessions.Remove(session);
            }
        }
        private readonly SemaphoreSlim issuerSynchronization = new SemaphoreSlim(1, 1);

        internal async Task SynchronizeIssuerAsync(CancellationToken cancellation)
        {
            await issuerSynchronization.WaitAsync(cancellation);
            try
            {
                await SynchronizeIssuerCoreAsync(cancellation);
            }
            finally { issuerSynchronization.Release(); }
        }

        private async Task SynchronizeIssuerCoreAsync(CancellationToken cancellation)
        {
            for (int page = 0; page < 100; page++)
            {
                var position = store.Read(state => new { state.RevocationCursor, state.IssuerStateId });
                long after = position.RevocationCursor;
                JsonElement observed = await issuer.SendAsync(HttpMethod.Get, "emergency/revocations?after=" + after.ToString(System.Globalization.CultureInfo.InvariantCulture), null, cancellation);
                string issuerStateId = StrictJson.Text(observed, "state_id", 128);
                long generation;
                lock (store.Gate)
                {
                    if (store.Read(state => state.RevocationCursor != after || state.IssuerStateId != position.IssuerStateId))
                    {
                        throw new EmergencyFault(409, "synchronization_changed");
                    }
                    if (position.IssuerStateId != issuerStateId)
                    {
                        ResetIssuerState(issuerStateId);
                    }
                    after = store.Read(state => state.RevocationCursor);
                    generation = store.Read(state => state.Generation);
                }

                JsonElement keys = await issuer.SendAsync(HttpMethod.Get, "emergency/signing-keys", null, cancellation);
                CredentialVerifier.ValidateKeys(keys.GetRawText());
                JsonElement feed = await issuer.SendAsync(HttpMethod.Get, "emergency/revocations?after=" + after.ToString(System.Globalization.CultureInfo.InvariantCulture), null, cancellation);
                string confirmedStateId = StrictJson.Text(feed, "state_id", 128);
                if (confirmedStateId != issuerStateId)
                {
                    lock (store.Gate)
                    {
                        ResetIssuerState(confirmedStateId);
                    }
                    continue;
                }

                bool more = feed.GetProperty("has_more").GetBoolean();
                store.Update(state =>
                {
                    if (state.RevocationCursor != after || state.IssuerStateId != issuerStateId || state.Generation != generation)
                    {
                        throw new EmergencyFault(409, "synchronization_changed");
                    }
                    long cursor = after;
                    JsonElement events = feed.GetProperty("events");
                    if (events.GetArrayLength() > 100)
                    {
                        throw StrictJson.Bad();
                    }
                    foreach (JsonElement item in events.EnumerateArray())
                    {
                        long sequence = StrictJson.Integer(item, "sequence");
                        if (sequence <= cursor)
                        {
                            throw new EmergencyFault(409, "revocation_order_invalid");
                        }
                        string kind = StrictJson.Text(item, "kind"), target = StrictJson.Text(item, "id", 128);
                        if (kind == "binding")
                        {
                            Block(state, target);
                        }
                        else if (kind == "ec")
                        {
                            if (state.Credentials.TryGetValue(target, out RegistryEntry entry))
                            {
                                entry.Status = "blocked";
                            }
                        }
                        else
                        {
                            throw StrictJson.Bad();
                        }
                        cursor = sequence;
                    }
                    if (StrictJson.Integer(feed, "cursor") != cursor || (more && cursor == after))
                    {
                        throw StrictJson.Bad();
                    }
                    state.RevocationCursor = cursor;
                    state.SigningKeys = keys.GetRawText();
                    state.IssuerTrustRefreshRequired = false;
                    if (!more)
                    {
                        state.LastPoll = Now;
                        Audit(state, "online_sync_completed");
                    }
                    return true;
                });
                if (!more)
                {
                    foreach (string binding in store.Read(state => state.RemovalQueue.ToArray()))
                    {
                        await ReportRemovalAsync(binding, cancellation);
                    }
                    return;
                }
            }
            throw new EmergencyFault(409, "sync_more_pages_required");
        }

        private void ResetIssuerState(string issuerStateId)
        {
            bool reset = store.Update(state =>
            {
                bool hadState = state.IssuerStateId != null || state.Credentials.Count != 0 || state.Bindings.Count != 0
                    || state.RemovalQueue.Count != 0 || state.RevocationCursor != 0;
                foreach (string bindingId in state.Bindings.Keys.ToArray())
                {
                    Block(state, bindingId);
                }
                foreach (RegistryEntry entry in state.Credentials.Values)
                {
                    entry.Status = "blocked";
                }
                state.Sessions.Clear();
                state.RemovalQueue.Clear();
                if (hadState)
                {
                    state.Generation++;
                    Audit(state, "issuer_state_changed_new_preparation_required");
                }
                state.LastPoll = 0;
                state.IssuerStateId = issuerStateId;
                state.RevocationCursor = 0;
                state.SigningKeys = null;
                state.IssuerTrustRefreshRequired = true;
                return hadState;
            });
            if (reset)
            {
                logins.Clear();
                enrollments.Clear();
                challenges.Clear();
            }
        }
        private async Task ReportRemovalAsync(string id, CancellationToken cancellation)
        {
            await issuer.SendAsync(HttpMethod.Post, "emergency/revocations", new
            {
                binding_id = id
            }, cancellation);
            store.Update(state => state.RemovalQueue.Remove(id));
        }
        public void Rate(string address)
        {
            lock (store.Gate)
            {
                foreach (string key in rates.Keys.ToArray())
                {
                    while (rates[key].Count != 0 && rates[key].Peek() <= Now - 60)
                    {
                        rates[key].Dequeue();
                    }
                    if (rates[key].Count == 0)
                    {
                        rates.Remove(key);
                    }
                }
                string id = StrictJson.Hash(address ?? "unknown");
                if (!rates.TryGetValue(id, out Queue<long> attempts))
                {
                    if (rates.Count >= 4096)
                    {
                        throw new EmergencyFault(429, "rate_limited");
                    }
                    rates.Add(id, attempts = new Queue<long>());
                }
                if (attempts.Count >= 60)
                {
                    throw new EmergencyFault(429, "rate_limited");
                }
                attempts.Enqueue(Now);
            }
        }
        private void Cleanup()
        {
            foreach (string id in logins.Where(pair => pair.Value.ForgetAfter <= Now).Select(pair => pair.Key).ToArray())
            {
                logins.Remove(id);
            }
            foreach (string id in enrollments.Where(pair => pair.Value.Expires <= Now).Select(pair => pair.Key).ToArray())
            {
                enrollments.Remove(id);
            }
            foreach (string id in challenges.Where(pair => pair.Value.Expires <= Now).Select(pair => pair.Key).ToArray())
            {
                challenges.Remove(id);
            }
        }
        private void Audit(LocalState state, string code)
        {
            state.Audit.Add(Now.ToString(System.Globalization.CultureInfo.InvariantCulture) + " " + code);
            if (state.Audit.Count > 200)
            {
                state.Audit.RemoveAt(0);
            }
        }
        public void Dispose()
        {
            store.Dispose();
        }
    }
}
