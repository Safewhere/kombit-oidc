using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using WebAppNetCore.Controllers;
using WebAppNetCore.EmergencyCredential;

namespace WebAppNetCore.Emergency.Tests
{
    [TestClass]
    public class HttpBoundaryTests
    {
        internal static TestServer Host(ProtocolFixture fixture, bool enabled, bool normalLogin = false)
        {
            fixture.Service.Dispose();
            fixture.Options.Enabled = enabled;
            var configuration = new ConfigurationBuilder().AddJsonStream(new MemoryStream(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
            {
                EmergencyCredential = fixture.Options
            })))).Build();
            string content = Path.Combine(fixture.Root, "application");
            Directory.CreateDirectory(content);
            return new TestServer(new WebHostBuilder().UseContentRoot(content).ConfigureServices(services =>
            {
                services.AddSingleton<IConfiguration>(configuration);
                services.AddMvc(options => options.EnableEndpointRouting = false).AddApplicationPart(typeof(EmergencyController).Assembly);
                var authentication = services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie();
                if (normalLogin)
                {
                    authentication.AddOpenIdConnect(options =>
                    {
                        options.ClientId = "normal-client";
                        options.ResponseType = "code";
                        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                        options.Configuration = new OpenIdConnectConfiguration { Issuer = fixture.Options.NormalIssuer, AuthorizationEndpoint = fixture.Options.NormalIssuer + "/authorize" };
                    });
                }
                services.AddEmergencyCredential(configuration);
            }).Configure(app =>
            {
                app.ApplicationServices.GetRequiredService<EmergencyRuntime>();
                app.UseAuthentication();
                app.UseMiddleware<EmergencyMiddleware>();
                if (normalLogin)
                {
                    app.Map("/test-normal-login", branch => branch.Run(async context =>
                    {
                        var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.NameIdentifier, "synthetic-user") }, CookieAuthenticationDefaults.AuthenticationScheme));
                        await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
                        context.Response.StatusCode = 204;
                    }));
                }
                app.UseMvc();
            }));
        }
        [DataTestMethod]
        [DataRow(false, "https", 404)]
        [DataRow(true, "http", 403)]
        public async Task Page_DisabledOrInsecure_ReturnsLocalError(bool enabled, string scheme, int status)
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            using var server = Host(fixture, enabled);
            using var client = server.CreateClient();
            // Act
            var response = await client.GetAsync(scheme + "://oidc.fixture.invalid/emergency/login");
            // Assert
            Assert.AreEqual(status, (int)response.StatusCode);
            Assert.AreEqual(0, fixture.Requests);
            StringAssert.Contains(response.Headers.CacheControl.ToString(), "no-store");
        }
        [TestMethod]
        public async Task LoginPage_AntiforgeryAndOriginGuards_WorkThroughHttpPipeline()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            using var server = Host(fixture, true);
            using var client = server.CreateClient();
            var cookies = new Dictionary<string, string>();
            var page = await client.GetAsync(fixture.Options.Origin + "/emergency/login");
            Assert.AreEqual(HttpStatusCode.OK, page.StatusCode);
            SaveCookies(page, cookies);
            string html = await page.Content.ReadAsStringAsync();
            string csrf = WebUtility.HtmlDecode(Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value);
            Assert.IsFalse(string.IsNullOrEmpty(csrf));
            StringAssert.Contains(html, "Identify endpoint results (PoC)");
            Assert.AreEqual("[]", Encoding.UTF8.GetString(Convert.FromBase64String(page.Headers.GetValues("X-Emergency-Issuer-Calls").Single())));
            // Act and Assert
            var missing = await Post(client, fixture, "signout", new { }, cookies, null);
            Assert.AreEqual(HttpStatusCode.Forbidden, missing.StatusCode);
            using var failureJson = JsonDocument.Parse(await missing.Content.ReadAsStringAsync());
            Assert.AreEqual(missing.Headers.GetValues("X-Emergency-Reference").Single(), failureJson.RootElement.GetProperty("reference_id").GetString());
            var crossOrigin = await Post(client, fixture, "signout", new { }, cookies, csrf, "https://wrong.invalid");
            Assert.AreEqual(HttpStatusCode.Forbidden, crossOrigin.StatusCode);
            var signedOut = await Post(client, fixture, "signout", new { }, cookies, csrf);
            Assert.AreEqual(HttpStatusCode.OK, signedOut.StatusCode);
            Assert.AreEqual(0, fixture.Requests);
        }
        [TestMethod]
        public async Task Prepare_NormalSession_RendersLoginNavigationWithoutFormSubmission()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            using var server = Host(fixture, true, normalLogin: true);
            using var client = server.CreateClient();
            var cookies = new Dictionary<string, string>();
            using var signIn = await client.GetAsync(fixture.Options.Origin + "/test-normal-login");
            SaveCookies(signIn, cookies);
            using var request = new HttpRequestMessage(HttpMethod.Get, fixture.Options.Origin + "/emergency");
            request.Headers.Add("Cookie", string.Join("; ", cookies.Select(cookie => cookie.Key + "=" + cookie.Value)));

            // Act
            using var response = await client.SendAsync(request);
            string html = await response.Content.ReadAsStringAsync();

            // Assert
            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.IsTrue(Regex.IsMatch(html, "<a[^>]+id=\"normal-login\"[^>]+href=\"/emergency/normal-login\""));
            Assert.IsFalse(Regex.IsMatch(html, "<form[^>]+action=\"/emergency/normal-login\""));
            StringAssert.Contains(response.Headers.GetValues("Content-Security-Policy").Single(), "form-action 'self'");
            Assert.AreEqual(0, fixture.Requests);
        }

        [TestMethod]
        public async Task NormalLogin_GetNavigation_StartsOidcChallengeWithRestrictedFormPolicy()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            using var server = Host(fixture, true, normalLogin: true);
            using var client = server.CreateClient();

            // Act
            using var response = await client.GetAsync(fixture.Options.Origin + "/emergency/normal-login");

            // Assert
            Assert.AreEqual(HttpStatusCode.Redirect, response.StatusCode);
            Assert.AreEqual(new Uri(fixture.Options.NormalIssuer + "/authorize").GetLeftPart(UriPartial.Path), response.Headers.Location.GetLeftPart(UriPartial.Path));
            StringAssert.Contains(response.Headers.Location.Query, "client_id=normal-client");
            StringAssert.Contains(response.Headers.GetValues("Content-Security-Policy").Single(), "form-action 'self'");
            Assert.AreEqual(0, fixture.Requests);
        }
        private static async Task<HttpResponseMessage> Post(HttpClient client, ProtocolFixture fixture, string operation, object value, Dictionary<string, string> cookies, string csrf, string origin = null)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, fixture.Options.Origin + "/emergency/" + operation) { Content = new StringContent(JsonSerializer.Serialize(value), Encoding.UTF8, "application/json") };
            request.Headers.Add("Origin", origin ?? fixture.Options.Origin);
            request.Headers.Add("Cookie", string.Join("; ", cookies.Select(cookie => cookie.Key + "=" + cookie.Value)));
            if (csrf != null)
                request.Headers.Add("X-Emergency-CSRF", csrf);
            return await client.SendAsync(request);
        }
        private static void SaveCookies(HttpResponseMessage response, Dictionary<string, string> cookies)
        {
            if (!response.Headers.TryGetValues("Set-Cookie", out var values))
                return;
            foreach (string value in values)
            {
                string pair = value.Split(';')[0];
                int index = pair.IndexOf('=');
                cookies[pair.Substring(0, index)] = pair.Substring(index + 1);
            }
        }
    }
}
