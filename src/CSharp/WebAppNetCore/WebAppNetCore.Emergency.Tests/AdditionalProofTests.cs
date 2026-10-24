using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using WebAppNetCore.EmergencyCredential;

namespace WebAppNetCore.Emergency.Tests
{
    [TestClass]
    public class AdditionalProofTests
    {
        [DataTestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task Assertion_NonDiscoverableKeyWithoutUserHandle_Accepts(bool elliptic)
        {
            // Arrange
            using var fixture = new ProtocolFixture(elliptic);
            string login = fixture.Login();
            JsonElement issued = await fixture.Pending(login);
            JsonElement challenge = JsonSerializer.SerializeToElement(fixture.Service.Challenge(fixture.Browser, issued.GetProperty("emergency_credential").GetString(), "activate", login));
            JsonObject assertion = JsonNode.Parse(fixture.Assertion(challenge.GetProperty("publicKey"), 1).GetRawText()).AsObject();
            assertion["response"]["userHandle"] = null;
            // Act
            await fixture.Service.FinishAsync(fixture.Browser, challenge.GetProperty("transaction_id").GetString(), "activate", JsonSerializer.SerializeToElement(assertion), login, CancellationToken.None);
            // Assert
            Assert.AreEqual("active", JsonSerializer.SerializeToElement(fixture.Service.Status(login, fixture.Browser)).GetProperty("credentials")[0].GetProperty("status").GetString());
        }
        [TestMethod]
        public async Task Assertion_BothCountersZero_AcceptsFreshChallenges()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            string login = fixture.Login();
            JsonElement issued = await fixture.Pending(login);
            await fixture.Prove(issued, "activate", login, 0);
            // Act and Assert
            Assert.IsNotNull(await fixture.Prove(issued, "login", null, 0));
        }
        [TestMethod]
        public async Task Assertion_ReusedNonzeroCounter_Rejects()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            JsonElement issued = await fixture.Active();
            // Act and Assert
            await Assert.ThrowsExactlyAsync<EmergencyFault>(() => fixture.Prove(issued, "login", null, 1));
        }
        [TestMethod]
        public async Task OidcEvents_InterleavedValidatedTickets_PublishOnlyAcceptedRequestReferences()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            JsonElement pending = await fixture.Pending(fixture.Login());
            using var host = HttpBoundaryTests.Host(fixture, true);
            using var scopeA = host.Services.CreateScope();
            using var scopeB = host.Services.CreateScope();
            TokenValidatedContext a = Context(scopeA.ServiceProvider, fixture, "test-user");
            TokenValidatedContext b = Context(scopeB.ServiceProvider, fixture, "another-user");
            await EmergencyOidcEvents.StageAsync(a);
            await EmergencyOidcEvents.StageAsync(b);
            Assert.IsFalse(a.Properties.Items.ContainsKey("emergency_login"));
            Assert.IsFalse(b.Properties.Items.ContainsKey("emergency_login"));
            // Act
            await EmergencyOidcEvents.AcceptedAsync(new TicketReceivedContext(b.HttpContext, b.Scheme, b.Options, new AuthenticationTicket(b.Principal, b.Properties, "Cookies")));
            await EmergencyOidcEvents.AcceptedAsync(new TicketReceivedContext(a.HttpContext, a.Scheme, a.Options, new AuthenticationTicket(a.Principal, a.Properties, "Cookies")));
            // Assert
            var service = host.Services.GetRequiredService<EmergencyRuntime>().Service;
            string token = pending.GetProperty("emergency_credential").GetString();
            Assert.ThrowsExactly<EmergencyFault>(() => service.Challenge(EmergencyBrowser.Read(b.HttpContext), token, "activate", b.Properties.Items["emergency_login"]));
            Assert.IsNotNull(service.Challenge(EmergencyBrowser.Read(a.HttpContext), token, "activate", a.Properties.Items["emergency_login"]));
        }
        [DataTestMethod]
        [DataRow("uv")][DataRow("backup")][DataRow("backedUp")]
        public async Task PocUp_AcceptsPresenceAndValidBackupStates(string mutation)
        {
            using var fixture = new ProtocolFixture(); string login = fixture.Login(); var entry = await fixture.Pending(login);
            var challenge = JsonSerializer.SerializeToElement(fixture.Service.Challenge(fixture.Browser, entry.GetProperty("emergency_credential").GetString(), "activate", login));
            Assert.AreEqual("preferred", challenge.GetProperty("publicKey").GetProperty("userVerification").GetString());
            await fixture.Service.FinishAsync(fixture.Browser, challenge.GetProperty("transaction_id").GetString(), "activate", fixture.Assertion(challenge.GetProperty("publicKey"), 1, mutation), login, CancellationToken.None);
            Assert.AreEqual("active", JsonSerializer.SerializeToElement(fixture.Service.Status(login, fixture.Browser)).GetProperty("credentials")[0].GetProperty("status").GetString());
        }
        private static TokenValidatedContext Context(IServiceProvider services, ProtocolFixture fixture, string subject)
        {
            var http = new DefaultHttpContext { RequestServices = services };
            http.Request.Scheme = "https";
            http.Request.Host = new HostString("oidc.fixture.invalid");
            var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.NameIdentifier, "userinfo-" + subject) }, "Cookies"));
            var scheme = new AuthenticationScheme("OpenIdConnect", "OpenIdConnect", typeof(OpenIdConnectHandler));
            var context = new TokenValidatedContext(http, scheme, new OpenIdConnectOptions(), principal, new AuthenticationProperties());
            context.SecurityToken = new JwtSecurityToken(fixture.Options.NormalIssuer, "normal-client", new[] { new Claim("sub", subject), new Claim("jti", StrictJson.Id()), new Claim("iat", fixture.Clock.Value.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture), ClaimValueTypes.Integer64) }, fixture.Clock.Value.UtcDateTime, fixture.Clock.Value.AddMinutes(10).UtcDateTime);
            return context;
        }
    }
}
