using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using WebAppNetCore.EmergencyCredential;

namespace WebAppNetCore.Emergency.Tests
{
    [TestClass]
    public class EmergencyBehaviorTests
    {
        [TestMethod]
        public async Task Restart_ChangedPocOrigin_PreservesRegistryWithoutHashApproval()
        {
            using var fixture = new ProtocolFixture();
            await fixture.Active();
            fixture.Options.Origin = "https://changed.fixture.invalid";
            fixture.Options.RelyingPartyId = "changed.fixture.invalid";
            fixture.Restart();
            var status = JsonSerializer.SerializeToElement(fixture.Service.Status(fixture.Login(), fixture.Browser));
            Assert.AreEqual(1, status.GetProperty("credentials").GetArrayLength());
        }

        [TestMethod]
        public async Task LoginVisibility_UsesLocalActiveStateOffline()
        {
            using var fixture = new ProtocolFixture();
            string login = fixture.Login();
            JsonElement pending = await fixture.Pending(login);
            string compact = pending.GetProperty("emergency_credential").GetString();
            Assert.IsFalse(fixture.Service.IsActiveForLogin(compact));
            await fixture.Prove(pending, "activate", login, 1);
            fixture.Offline = true;
            int requests = fixture.Requests;
            Assert.IsTrue(fixture.Service.IsActiveForLogin(compact));
            Assert.IsFalse(fixture.Service.IsActiveForLogin("invalid"));
            Assert.AreEqual(requests, fixture.Requests);
            fixture.Restart();
            Assert.IsTrue(fixture.Service.IsActiveForLogin(compact));
            await fixture.Service.RemoveAsync(fixture.Login(), fixture.Browser, pending.GetProperty("binding_id").GetString(), CancellationToken.None);
            Assert.IsFalse(fixture.Service.IsActiveForLogin(compact));
        }

        [TestMethod]
        public void BackendKey_UsesConfiguredPocTextWithoutEnvironment()
        {
            Assert.AreEqual("poc-key", new EmergencyOptions { ApiKey = "poc-key" }.BackendKey());
        }

        [DataTestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task Lifecycle_PrepareOfflineRestartAndLogin_EnforcesLocalState(bool elliptic)
        {
            // Arrange
            using var fixture = new ProtocolFixture(elliptic);
            JsonElement active = await fixture.Active();
            int requests = fixture.Requests;
            fixture.Offline = true;

            // Act
            fixture.Restart();
            var session = await fixture.Prove(active, "login", null, 2);
            var principal = fixture.Service.Session(session.Id, fixture.Browser);

            // Assert
            Assert.IsNotNull(principal);
            Assert.IsTrue(principal.HasClaim("ROLE", "case-admin"));
            Assert.IsTrue(principal.Claims.Any(claim => claim.Value == "normal-evidence"));
            Assert.AreEqual(2, principal.FindAll("department").Count());
            Assert.AreEqual("Synthetic User", principal.Identity.Name);
            Assert.AreEqual("user@example.invalid", principal.FindFirst("email").Value);
            Assert.AreEqual(System.Security.Claims.ClaimValueTypes.Integer, principal.FindFirst("level").ValueType);
            Assert.AreEqual(requests, fixture.Requests);
            Assert.AreEqual(1, principal.FindAll("emergency_session_id").Count());
            Assert.AreEqual(session.Id, principal.FindFirst("emergency_session_id").Value);
            Assert.IsNotNull(principal.FindFirst("acr"));
            Assert.IsNotNull(principal.FindFirst("access_token"));
            CollectionAssert.AreEquivalent(new[] { "case-admin", "read-only", "administrator" }, principal.FindAll("role").Select(claim => claim.Value).ToArray());
            Assert.IsNull(fixture.Service.Session(session.Id, "another-browser"));
            fixture.Service.SignOut(session.Id);
            Assert.IsNull(fixture.Service.Session(session.Id, fixture.Browser));
        }

        [DataTestMethod]
        [DataRow("audience")]
        [DataRow("audience-array")]
        [DataRow("issuer")]
        [DataRow("expired")]
        [DataRow("long-lifetime")]
        [DataRow("profile")]
        [DataRow("source")]
        [DataRow("rp")]
        [DataRow("origin")]
        [DataRow("hardware")]
        [DataRow("type")]
        [DataRow("unknown-key")]
        [DataRow("external-key")]
        [DataRow("critical")]
        [DataRow("none")]
        [DataRow("duplicate")]
        [DataRow("tampered")]
        public void Credential_InvalidSignedProfile_Rejects(string mutation)
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            string token = fixture.Issue(mutation).GetProperty("emergency_credential").GetString();
            // Act and Assert
            Assert.ThrowsExactly<EmergencyFault>(() => fixture.Verifier.Verify(token, fixture.Trust, fixture.Clock.Value));
        }

        [DataTestMethod]
        [DataRow("up")]
        [DataRow("invalid-backup-state")]
        [DataRow("type")]
        [DataRow("challenge")]
        [DataRow("origin")]
        [DataRow("rp")]
        [DataRow("id")]
        [DataRow("handle")]
        [DataRow("signature")]
        [DataRow("crossOrigin")]
        [DataRow("topOrigin")]
        public async Task Assertion_InvalidProof_RejectsAndConsumesAttempt(string mutation)
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            string login = fixture.Login();
            JsonElement pending = await fixture.Pending(login);
            JsonElement challenge = JsonSerializer.SerializeToElement(fixture.Service.Challenge(fixture.Browser, pending.GetProperty("emergency_credential").GetString(), "activate", login));
            string id = challenge.GetProperty("transaction_id").GetString();
            JsonElement invalid = fixture.Assertion(challenge.GetProperty("publicKey"), 1, mutation);
            // Act and Assert
            await Assert.ThrowsExactlyAsync<EmergencyFault>(() => fixture.Service.FinishAsync(fixture.Browser, id, "activate", invalid, login, CancellationToken.None));
            await Assert.ThrowsExactlyAsync<EmergencyFault>(() => fixture.Service.FinishAsync(fixture.Browser, id, "activate", fixture.Assertion(challenge.GetProperty("publicKey"), 1), login, CancellationToken.None));
        }

        [TestMethod]
        public async Task Renewal_ActivationFailureThenSuccess_PreservesOldUntilReplacement()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            JsonElement old = await fixture.Active();
            fixture.Clock.Advance(1);
            string login = fixture.Login();
            JsonElement renewed = await fixture.Service.RenewAsync(login, fixture.Browser, fixture.Binding, CancellationToken.None);
            // Act
            var session = await fixture.Prove(old, "login", null, 2);
            await fixture.Prove(renewed, "activate", login, 3);
            // Assert
            Assert.IsNull(fixture.Service.Session(session.Id, fixture.Browser));
            Assert.ThrowsExactly<EmergencyFault>(() => fixture.Service.Challenge(fixture.Browser, old.GetProperty("emergency_credential").GetString(), "login", null));
            var replacement = await fixture.Prove(renewed, "login", null, 4);
            Assert.IsNotNull(fixture.Service.Session(replacement.Id, fixture.Browser));
        }

        [TestMethod]
        public async Task ConcurrentChallenges_OnlyOneRevisionCanCommit()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            JsonElement entry = await fixture.Active();
            string token = entry.GetProperty("emergency_credential").GetString();
            JsonElement first = JsonSerializer.SerializeToElement(fixture.Service.Challenge(fixture.Browser, token, "login", null));
            JsonElement second = JsonSerializer.SerializeToElement(fixture.Service.Challenge(fixture.Browser, token, "login", null));
            // Act
            await fixture.Service.FinishAsync(fixture.Browser, first.GetProperty("transaction_id").GetString(), "login", fixture.Assertion(first.GetProperty("publicKey"), 2), null, CancellationToken.None);
            // Assert
            await Assert.ThrowsExactlyAsync<EmergencyFault>(() => fixture.Service.FinishAsync(fixture.Browser, second.GetProperty("transaction_id").GetString(), "login", fixture.Assertion(second.GetProperty("publicKey"), 3), null, CancellationToken.None));
        }

        [TestMethod]
        public async Task Remove_Offline_DeletesLocalRecordsAndQueuesReport()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            JsonElement entry = await fixture.Active();
            string login = fixture.Login();
            var session = await fixture.Prove(entry, "login", null, 2);
            fixture.Offline = true;
            // Act
            await fixture.Service.RemoveAsync(login, fixture.Browser, fixture.Binding, CancellationToken.None);
            // Assert
            Assert.IsNull(fixture.Service.Session(session.Id, fixture.Browser));
            Assert.AreEqual(0, JsonSerializer.SerializeToElement(fixture.Service.Status(login, fixture.Browser)).GetProperty("credentials").GetArrayLength());
            Assert.ThrowsExactly<EmergencyFault>(() => fixture.Service.Challenge(fixture.Browser, entry.GetProperty("emergency_credential").GetString(), "login", null));
            fixture.Restart();
            Assert.AreEqual(0, JsonSerializer.SerializeToElement(fixture.Service.Status(fixture.Login(), fixture.Browser)).GetProperty("credentials").GetArrayLength());
            Assert.AreEqual(1, QueuedRemovals(fixture));
            Assert.IsNull(fixture.Service.Session(session.Id, fixture.Browser));
            fixture.Offline = false;
            await fixture.Service.SynchronizeIssuerAsync(CancellationToken.None);
            Assert.AreEqual(0, QueuedRemovals(fixture));
        }

        [TestMethod]
        public async Task ExpiryAndRestart_RequiresNewLoginEvidenceAndRejectsPendingAccess()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            string login = fixture.Login();
            JsonElement pending = await fixture.Pending(login);
            // Act and Assert
            Assert.ThrowsExactly<EmergencyFault>(() => fixture.Service.Challenge(fixture.Browser, pending.GetProperty("emergency_credential").GetString(), "login", null));
            fixture.Restart();
            Assert.IsFalse(fixture.Service.HasLogin(login, fixture.Browser));
            string another = fixture.Login();
            fixture.Clock.Advance(601);
            await Assert.ThrowsExactlyAsync<EmergencyFault>(() => fixture.Service.EnrollAsync(another, fixture.Browser, CancellationToken.None));
        }

        [TestMethod]
        public async Task DisabledMarker_EndsSessionsWithoutDeletingPreparedState()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            JsonElement entry = await fixture.Active();
            LocalSession session = await fixture.Prove(entry, "login", null, 2);
            // Act
            File.WriteAllText(Path.Combine(fixture.Options.StorageDirectory, "support-disabled"), "1");
            fixture.Restart();
            // Assert
            Assert.IsNull(fixture.Service.Session(session.Id, fixture.Browser));
            Assert.IsNotNull(await fixture.Prove(entry, "login", null, 3));
        }

        [TestMethod]
        public void StateOwnership_CompetingWriterAndMissingState_Reject()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            // Act and Assert
            Assert.ThrowsExactly<IOException>(() => new ProtectedStateStore(fixture.Options, fixture.Protection, fixture.Verifier));
            fixture.Service.Dispose();
            File.Delete(Path.Combine(fixture.Options.StorageDirectory, "state.bin"));
            Assert.ThrowsExactly<InvalidOperationException>(() => new ProtectedStateStore(fixture.Options, fixture.Protection, fixture.Verifier));
        }
        private static int QueuedRemovals(ProtocolFixture fixture)
        {
            fixture.Service.Dispose();
            int count;
            using (var state = new ProtectedStateStore(fixture.Options, fixture.Protection, fixture.Verifier))
            {
                count = state.Read(value => value.RemovalQueue.Count);
            }
            fixture.Restart();
            return count;
        }
    }
}
