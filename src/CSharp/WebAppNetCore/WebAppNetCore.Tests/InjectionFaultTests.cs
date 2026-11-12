using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using WebAppNetCore.OAuth;
using Xunit;

namespace WebAppNetCore.Tests;

/// <summary>
/// The faults that substitute or inject a value: the ID token as the access token at UserInfo, a refresh with a scope that was
/// not granted, another client at introspection and revocation, browser parameters next to request_uri, and keys in the header
/// of the client assertion. Each test checks the outgoing request at the stub Identify.
/// </summary>
public sealed class InjectionFaultTests
{
    private const string OtherClientId = "other-client";

    private static Dictionary<string, string?> Settings(bool dpop = false, bool par = true)
    {
        var settings = new Dictionary<string, string?>
        {
            ["Testing:EnableFaultInjection"] = "true",
            ["Testing:OtherClientId"] = OtherClientId
        };
        if (dpop)
        {
            settings["OpenIdConnectOptions:DPoP:BindAccessTokens"] = "true";
            settings["OpenIdConnectOptions:DPoP:SendDPoPJkt"] = "true";
        }

        if (par)
        {
            settings["OpenIdConnectOptions:PushedAuthorization"] = "Require";
        }

        return settings;
    }

    private static Dictionary<string, string?> PrivateKeyJwtSettings(TestCertificateFile certificate, bool dpop = false)
    {
        var settings = Settings(dpop);
        foreach (var setting in certificate.PrivateKeyJwtSettings())
        {
            settings[setting.Key] = setting.Value;
        }

        settings["OpenIdConnectOptions:ClientAssertion:Audience"] = "Issuer";
        return settings;
    }

    private static Dictionary<string, string> WithFault(Fault fault) => new() { [FaultInjection.FieldName] = fault.ToString() };

    private static RecordedRequest Single(TestWebApplicationFactory factory, string endpoint) => Assert.Single(factory.Identify.RequestsTo(endpoint));

    private static async Task<string> HomePageAsync(HttpClient client) => WebUtility.HtmlDecode(await client.GetStringAsync("/"));

    private static JsonElement Part(string jwt, int index) =>
        JsonDocument.Parse(Base64UrlEncoder.Decode(jwt.Split('.')[index])).RootElement.Clone();

    private static async Task<bool> VerifiesWithAsync(string jwt, SecurityKey key)
    {
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(jwt, new TokenValidationParameters
        {
            IssuerSigningKey = key,
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false
        });
        return result.IsValid;
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task IdTokenAtUserInfoSendsTheIdTokenWithTheBearerScheme(bool dpop)
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop, par: false));
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);
        var tokens = (await TestSession.GetAsync(client)).Tokens;
        factory.Identify.UserInfoResponder = _ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
            response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue("Bearer", "error=\"invalid_token\""));
            return response;
        };

        using var response = await SignInFlow.PostFormAsync(client, "/Account/UserInfo", WithFault(Fault.IdTokenAtUserInfo));
        var page = await HomePageAsync(client);

        var userInfo = factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint).Last();
        Assert.Equal(HttpMethod.Get, userInfo.Method);
        Assert.Equal("Bearer " + tokens["id_token"], userInfo.Header("Authorization"));
        Assert.NotEqual(tokens["id_token"], tokens["access_token"]);
        Assert.Null(userInfo.Header("DPoP"));
        Assert.Contains("The UserInfo endpoint returned HTTP 401: invalid_token", page);
        Assert.Contains("IdTokenAtUserInfo: the UserInfo request sends the ID token of the sign-in with the Bearer scheme", page);
    }

    [Fact]
    public async Task RefreshWiderScopeAsksForTheScopeOfTheSignInAndAScopeThatWasNotGranted()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true, par: false));
        using var client = SignInFlow.CreateHttpsClient(factory);
        var request = await SignInFlow.SignInAsync(client, factory);
        factory.Identify.TokenResponder = recorded => recorded.Form.ContainsKey("refresh_token")
            ? StubIdentify.OAuthError(HttpStatusCode.BadRequest, "invalid_scope", "The requested scope is invalid.")
            : factory.Identify.DefaultTokenResponse(recorded);

        using var response = await SignInFlow.PostFormAsync(client, "/Account/Refresh", WithFault(Fault.RefreshWiderScope));

        var refresh = factory.Identify.RequestsTo(StubIdentify.TokenEndpoint).Last();
        Assert.Equal("refresh_token", refresh.Form["grant_type"]);
        Assert.Equal(StubIdentify.RefreshToken, refresh.Form["refresh_token"]);
        Assert.Equal("openid " + TokenClient.NotGrantedScope, refresh.Form["scope"]);
        Assert.Equal(TestWebApplicationFactory.ClientSecret, refresh.Form["client_secret"]);
        var proof = await DPoPProof.ValidateAsync(refresh.Header("DPoP"), "POST", StubIdentify.TokenEndpoint);
        Assert.Equal(request.Parameters["dpop_jkt"], proof.Thumbprint);
        Assert.Contains("The token endpoint returned HTTP 400: invalid_scope", await HomePageAsync(client));
    }

    [Theory]
    [InlineData("/Account/Introspect", Fault.IntrospectAsOtherClient, StubIdentify.IntrospectionEndpoint)]
    [InlineData("/Account/Revoke", Fault.RevokeAsOtherClient, StubIdentify.RevocationEndpoint)]
    public async Task TokenManagementAsOtherClientAuthenticatesAsTheOtherClientWithTheClientKey(string path, Fault fault, string endpoint)
    {
        using var certificate = new TestCertificateFile();
        using var factory = new TestWebApplicationFactory(settings: PrivateKeyJwtSettings(certificate, dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);
        var accessToken = (await TestSession.GetAsync(client)).Tokens["access_token"];

        using var response = await SignInFlow.PostFormAsync(client, path, WithFault(fault));

        var form = Single(factory, endpoint).Form;
        Assert.Equal(accessToken, form["token"]);
        Assert.Equal("access_token", form["token_type_hint"]);
        Assert.Equal(OtherClientId, form["client_id"]);
        Assert.False(form.ContainsKey("client_secret"), "The request has the client secret.");
        var assertion = await CodeFlowTests.ValidateClientAssertionAsync(form["client_assertion"], certificate);
        Assert.Equal(OtherClientId, assertion.Issuer);
        Assert.Equal(OtherClientId, assertion.Subject);

        // The sign-in and the token requests are of this client.
        Assert.All(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint), r => Assert.Equal(TestWebApplicationFactory.ClientId, r.Form["client_id"]));
    }

    [Theory]
    [InlineData("/Account/Introspect", Fault.IntrospectAsOtherClient, StubIdentify.IntrospectionEndpoint)]
    [InlineData("/Account/Revoke", Fault.RevokeAsOtherClient, StubIdentify.RevocationEndpoint)]
    public async Task TheOtherClientFaultsAtTokenManagementNeedPrivateKeyJwt(string path, Fault fault, string endpoint)
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(par: false));
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);

        using var response = await SignInFlow.PostFormAsync(client, path, WithFault(fault));

        Assert.Contains($"The fault {fault} needs TokenAuthnMethod private_key_jwt and another connection with the same client keys", await HomePageAsync(client));
        Assert.Empty(factory.Identify.RequestsTo(endpoint));
    }

    [Fact]
    public async Task ExtraBrowserRedirectUriAddsAnotherRedirectUriNextToTheRequestUri()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings());
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.StartAsync(client, factory, WithFault(Fault.ExtraBrowserRedirectUri));

        Assert.Equal(new[] { "client_id", "redirect_uri", "request_uri" }, request.BrowserParameters.Keys.OrderBy(k => k, StringComparer.Ordinal));
        Assert.Equal("https://localhost/fault-redirect", request.BrowserParameters["redirect_uri"]);
        Assert.Equal(TestWebApplicationFactory.ClientId, request.BrowserParameters["client_id"]);
        Assert.Equal(StubIdentify.RequestUri, request.BrowserParameters["request_uri"]);
        // The pushed request has the redirect URI of the sign-in.
        Assert.Equal("https://localhost/signin-oidc", request.Parameters["redirect_uri"]);
    }

    [Fact]
    public async Task BrowserWithoutClientIdSendsOnlyTheRequestUri()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings());
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.StartAsync(client, factory, WithFault(Fault.BrowserWithoutClientId));

        Assert.Equal(StubIdentify.RequestUri, Assert.Single(request.BrowserParameters).Value);
        Assert.Equal("request_uri", request.BrowserParameters.Keys.Single());
        Assert.Equal(TestWebApplicationFactory.ClientId, request.Parameters["client_id"]);
    }

    [Theory]
    [InlineData(Fault.ExtraBrowserRedirectUri, "POST", true)]
    [InlineData(Fault.ExtraBrowserRedirectUri, "GET", false)]
    [InlineData(Fault.BrowserWithoutClientId, "POST", true)]
    [InlineData(Fault.BrowserWithoutClientId, "GET", false)]
    public async Task TheBrowserRequestFaultsStopTheSignInWithoutARedirectAfterThePush(Fault fault, string authorizationEndpointMethod, bool par)
    {
        using var factory = new TestWebApplicationFactory(authorizationEndpointMethod, Settings(par: par));
        using var client = SignInFlow.CreateHttpsClient(factory);

        using var response = await SignInFlow.PostSignInAsync(client, WithFault(fault));

        Assert.Equal(
            $"The fault {fault} needs AuthorizationEndpointMethod GET and a pushed authorization request. The sign-in did not start.",
            SignInFlow.ErrorMessage(await SignInFlow.AssertErrorPageAsync(client, response)));
        Assert.Empty(factory.Identify.RequestsTo(StubIdentify.ParEndpoint));
    }

    [Theory]
    [InlineData(Fault.AssertionHeaderJwk)]
    [InlineData(Fault.AssertionHeaderX5c)]
    [InlineData(Fault.AssertionHeaderJku)]
    public async Task AssertionHeaderKeyFaultsSignWithANewKeyThatTheHeaderNames(Fault fault)
    {
        using var certificate = new TestCertificateFile();
        using var factory = new TestWebApplicationFactory(settings: PrivateKeyJwtSettings(certificate));
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.StartAsync(client, factory, WithFault(fault));
        using var callback = await SignInFlow.CompleteAsync(client, factory, request);
        await SignInFlow.AssertSignedInAsync(client, callback);

        var clientKey = new X509SecurityKey(certificate.PublicCertificate);
        foreach (var endpoint in new[] { StubIdentify.ParEndpoint, StubIdentify.TokenEndpoint })
        {
            var form = Single(factory, endpoint).Form;
            var assertion = form["client_assertion"];
            var header = Part(assertion, 0);
            var payload = Part(assertion, 1);
            Assert.Equal(TestWebApplicationFactory.ClientId, form["client_id"]);
            Assert.Equal(TestWebApplicationFactory.ClientId, payload.GetProperty("iss").GetString());
            Assert.Equal(TestWebApplicationFactory.ClientId, payload.GetProperty("sub").GetString());
            Assert.Equal(StubIdentify.Issuer, payload.GetProperty("aud").GetString());
            Assert.False(string.IsNullOrEmpty(payload.GetProperty("jti").GetString()));
            Assert.False(header.TryGetProperty("kid", out _), "The header has a kid.");
            Assert.False(header.TryGetProperty("x5t", out _), "The header has x5t.");
            Assert.False(await VerifiesWithAsync(assertion, clientKey), "The assertion verifies with the client key.");
            Assert.Equal(fault == Fault.AssertionHeaderJwk, header.TryGetProperty("jwk", out var jwk));
            Assert.Equal(fault == Fault.AssertionHeaderX5c, header.TryGetProperty("x5c", out var x5c));
            Assert.Equal(fault == Fault.AssertionHeaderJku, header.TryGetProperty("jku", out var jku));
            switch (fault)
            {
                case Fault.AssertionHeaderJwk:
                    Assert.Equal(new[] { "e", "kty", "n" }, jwk.EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal));
                    Assert.True(await VerifiesWithAsync(assertion, new JsonWebKey(jwk.GetRawText())));
                    break;
                case Fault.AssertionHeaderX5c:
                    using (var headerCertificate = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(x5c[0].GetString()!)))
                    {
                        Assert.False(headerCertificate.HasPrivateKey);
                        Assert.True(await VerifiesWithAsync(assertion, new X509SecurityKey(headerCertificate)));
                    }

                    break;
                default:
                    Assert.Equal(ClientAuthentication.HeaderJkuUrl, jku.GetString());
                    break;
            }
        }
    }

    [Fact]
    public async Task TheNewFaultsAreShownInTheirForms()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);

        var anonymousPage = WebUtility.HtmlDecode(await client.GetStringAsync("/"));
        foreach (var fault in new[] { Fault.ExtraBrowserRedirectUri, Fault.BrowserWithoutClientId, Fault.AssertionHeaderJwk, Fault.AssertionHeaderX5c, Fault.AssertionHeaderJku })
        {
            Assert.Contains($"<option value=\"{fault}\">{fault}: " + FaultInjection.Describe(fault), anonymousPage);
        }

        await SignInFlow.SignInAsync(client, factory);
        var page = await client.GetStringAsync("/");
        foreach (var fault in new[] { Fault.IdTokenAtUserInfo, Fault.RefreshWiderScope, Fault.IntrospectAsOtherClient, Fault.RevokeAsOtherClient })
        {
            Assert.Contains($"value=\"{fault}\"", page);
            Assert.NotEqual(string.Empty, FaultInjection.Describe(fault));
        }
    }

    [Fact]
    public async Task TheNewFaultsAreIgnoredWhenFaultInjectionIsOff()
    {
        var settings = Settings(dpop: true, par: false);
        settings["Testing:EnableFaultInjection"] = "false";
        using var factory = new TestWebApplicationFactory(settings: settings);
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);
        var accessToken = (await TestSession.GetAsync(client)).Tokens["access_token"];

        using var userInfoResponse = await SignInFlow.PostFormAsync(client, "/Account/UserInfo", WithFault(Fault.IdTokenAtUserInfo));
        using var refreshResponse = await SignInFlow.PostFormAsync(client, "/Account/Refresh", WithFault(Fault.RefreshWiderScope));

        Assert.Equal("DPoP " + accessToken, factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint).Last().Header("Authorization"));
        Assert.False(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint).Last().Form.ContainsKey("scope"), "The refresh request has a scope.");
    }
}
