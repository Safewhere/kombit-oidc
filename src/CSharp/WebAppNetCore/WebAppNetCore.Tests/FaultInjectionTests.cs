using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Text.Json;
using WebAppNetCore.OAuth;
using Xunit;

namespace WebAppNetCore.Tests;

public sealed class FaultInjectionTests
{
    private static Dictionary<string, string?> Settings(bool enableFaultInjection = true, bool dpop = false, bool par = false)
    {
        var settings = new Dictionary<string, string?>
        {
            ["Testing:EnableFaultInjection"] = enableFaultInjection.ToString()
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

    private static Dictionary<string, string> WithFault(Fault fault) => new() { [FaultInjection.FieldName] = fault.ToString() };

    private static async Task<AuthorizationRequest> SignInWithFaultAsync(HttpClient client, TestWebApplicationFactory factory, Fault fault)
    {
        var request = await SignInFlow.StartAsync(client, factory, WithFault(fault));
        using var callback = await SignInFlow.CompleteAsync(client, factory, request);
        await SignInFlow.AssertSignedInAsync(client, callback);
        return request;
    }

    [Fact]
    public async Task FaultsAreIgnoredAndHiddenWhenFaultInjectionIsOff()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(enableFaultInjection: false, par: true));
        using var client = SignInFlow.CreateHttpsClient(factory);

        Assert.DoesNotContain("Fault injection (negative test)", await client.GetStringAsync("/"));
        var request = await SignInFlow.StartAsync(client, factory, WithFault(Fault.SkipPar));

        Assert.True(request.BrowserParameters.ContainsKey("request_uri"));
    }

    [Fact]
    public async Task TheFaultListsAreShownWhenFaultInjectionIsOn()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);

        var anonymousPage = WebUtility.HtmlDecode(await client.GetStringAsync("/"));
        Assert.Contains("<option value=\"SkipPar\">SkipPar: " + FaultInjection.Describe(Fault.SkipPar), anonymousPage);
        Assert.DoesNotContain("value=\"MissingAth\"", anonymousPage);

        await SignInFlow.SignInAsync(client, factory);
        var page = await client.GetStringAsync("/");
        Assert.Contains("value=\"MissingAth\"", page);
        Assert.Contains("value=\"NewDPoPKeyOnRefresh\"", page);
    }

    [Fact]
    public async Task AFaultOfAnotherActionIsIgnored()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInWithFaultAsync(client, factory, Fault.MissingAth);

        var userInfo = Assert.Single(factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint));
        var accessToken = (await TestSession.GetAsync(client)).Tokens["access_token"];
        await DPoPProof.ValidateAsync(userInfo.Header("DPoP"), "GET", StubIdentify.UserInfoEndpoint, accessToken);
    }

    [Fact]
    public async Task SkipParSendsTheDirectRequest()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(par: true));
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.StartAsync(client, factory, WithFault(Fault.SkipPar));

        Assert.False(request.BrowserParameters.ContainsKey("request_uri"));
        Assert.Equal("code", request.BrowserParameters["response_type"]);
        Assert.Empty(factory.Identify.RequestsTo(StubIdentify.ParEndpoint));
    }

    [Fact]
    public async Task ExtraBrowserParameterAddsScopeNextToTheRequestUri()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(par: true));
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.StartAsync(client, factory, WithFault(Fault.ExtraBrowserParameter));

        Assert.Equal(new[] { "client_id", "request_uri", "scope" }, request.BrowserParameters.Keys.OrderBy(k => k));
        Assert.Equal("openid", request.BrowserParameters["scope"]);
    }

    [Theory]
    [InlineData("POST", true)]
    [InlineData("GET", false)]
    public async Task ExtraBrowserParameterStopsTheSignInWithoutARedirectAfterThePush(string authorizationEndpointMethod, bool par)
    {
        // With POST the handler writes a form, and without PAR there is no request_uri, so the fault cannot change the request.
        using var factory = new TestWebApplicationFactory(authorizationEndpointMethod, Settings(par: par));
        using var client = SignInFlow.CreateHttpsClient(factory);

        using var response = await SignInFlow.PostSignInAsync(client, WithFault(Fault.ExtraBrowserParameter));

        Assert.Equal(
            "The fault ExtraBrowserParameter needs AuthorizationEndpointMethod GET and a pushed authorization request. The sign-in did not start.",
            SignInFlow.ErrorMessage(await SignInFlow.AssertErrorPageAsync(client, response)));
        Assert.Empty(factory.Identify.RequestsTo(StubIdentify.ParEndpoint));
    }

    [Theory]
    [InlineData(Fault.AssertionAudienceArray)]
    [InlineData(Fault.AssertionFutureIat)]
    public async Task AssertionFaultsChangeTheAssertionsAtParAndAtTheTokenEndpoint(Fault fault)
    {
        using var certificate = new TestCertificateFile();
        var settings = Settings(par: true);
        foreach (var setting in certificate.PrivateKeyJwtSettings())
        {
            settings[setting.Key] = setting.Value;
        }

        settings["OpenIdConnectOptions:ClientAssertion:Audience"] = "Issuer";
        using var factory = new TestWebApplicationFactory(settings: settings);
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInWithFaultAsync(client, factory, fault);

        var assertions = new[] { StubIdentify.ParEndpoint, StubIdentify.TokenEndpoint }
            .Select(endpoint => new JsonWebToken(Assert.Single(factory.Identify.RequestsTo(endpoint)).Form["client_assertion"]));
        foreach (var assertion in assertions)
        {
            using var payload = JsonDocument.Parse(Base64UrlEncoder.Decode(assertion.EncodedPayload));
            if (fault == Fault.AssertionAudienceArray)
            {
                var audience = payload.RootElement.GetProperty("aud");
                Assert.Equal(JsonValueKind.Array, audience.ValueKind);
                Assert.Equal(StubIdentify.Issuer, Assert.Single(audience.EnumerateArray()).GetString());
            }
            else
            {
                var issuedAt = DateTimeOffset.FromUnixTimeSeconds(payload.RootElement.GetProperty("iat").GetInt64());
                Assert.InRange(issuedAt, DateTimeOffset.UtcNow.AddSeconds(90), DateTimeOffset.UtcNow.AddSeconds(150));
            }
        }
    }

    [Fact]
    public async Task ParProofKeyMismatchSignsTheParProofWithAnotherKey()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true, par: true));
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInWithFaultAsync(client, factory, Fault.ParProofKeyMismatch);

        var par = Assert.Single(factory.Identify.RequestsTo(StubIdentify.ParEndpoint));
        var parProof = await DPoPProof.ValidateAsync(par.Header("DPoP"), "POST", StubIdentify.ParEndpoint);
        Assert.NotEqual(par.Form["dpop_jkt"], parProof.Thumbprint);
        var tokenProof = DPoPProof.Read(Assert.Single(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint)).Header("DPoP")!);
        Assert.Equal(par.Form["dpop_jkt"], tokenProof.Thumbprint);
    }

    [Fact]
    public async Task NoDPoPProofOmitsTheTokenProof()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInWithFaultAsync(client, factory, Fault.NoDPoPProof);

        Assert.Null(Assert.Single(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint)).Header("DPoP"));
    }

    [Fact]
    public async Task WrongDPoPKeySignsTheTokenProofWithAnotherKey()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInWithFaultAsync(client, factory, Fault.WrongDPoPKey);

        var tokenProof = await DPoPProof.ValidateAsync(
            Assert.Single(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint)).Header("DPoP"), "POST", StubIdentify.TokenEndpoint);
        Assert.NotEqual(request.Parameters["dpop_jkt"], tokenProof.Thumbprint);
        // The key of the sign-in is unchanged: UserInfo uses it.
        var userInfoProof = DPoPProof.Read(Assert.Single(factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint)).Header("DPoP")!);
        Assert.Equal(request.Parameters["dpop_jkt"], userInfoProof.Thumbprint);
    }

    [Fact]
    public async Task WrongHtuUsesTheAuthorizationEndpoint()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInWithFaultAsync(client, factory, Fault.WrongHtu);

        await DPoPProof.ValidateAsync(
            Assert.Single(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint)).Header("DPoP"), "POST", StubIdentify.AuthorizationEndpoint);
    }

    [Fact]
    public async Task SmallDPoPKeySignsTheTokenProofWithAnRsa1024Key()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInWithFaultAsync(client, factory, Fault.SmallDPoPKey);

        var proof = await DPoPProof.ValidateAsync(
            Assert.Single(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint)).Header("DPoP"), "POST", StubIdentify.TokenEndpoint);
        Assert.Equal(128, Base64UrlEncoder.DecodeBytes(proof.Header.GetProperty("jwk").GetProperty("n").GetString()).Length);
    }

    [Fact]
    public async Task RedeemCodeTwiceSendsASecondRedemptionAndContinues()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings());
        factory.Identify.TokenResponder = recorded => factory.Identify.RequestsTo(StubIdentify.TokenEndpoint).Count > 1
            ? StubIdentify.OAuthError(HttpStatusCode.BadRequest, "invalid_grant", "The code was used.")
            : factory.Identify.DefaultTokenResponse(recorded);
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInWithFaultAsync(client, factory, Fault.RedeemCodeTwice);

        var tokenRequests = factory.Identify.RequestsTo(StubIdentify.TokenEndpoint);
        Assert.Equal(2, tokenRequests.Count);
        Assert.All(tokenRequests, r => Assert.Equal(SignInFlow.Code, r.Form["code"]));
        Assert.Contains(
            "RedeemCodeTwice: the second redemption failed: The token endpoint returned HTTP 400: invalid_grant (The code was used.)",
            await client.GetStringAsync("/"));
    }

    [Fact]
    public async Task BearerAtUserInfoSendsTheDPoPTokenWithTheBearerScheme()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);

        using var response = await SignInFlow.PostFormAsync(client, "/Account/UserInfo", WithFault(Fault.BearerAtUserInfo));

        var userInfo = factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint).Last();
        Assert.Equal("Bearer " + (await TestSession.GetAsync(client)).Tokens["access_token"], userInfo.Header("Authorization"));
        Assert.Null(userInfo.Header("DPoP"));
    }

    [Fact]
    public async Task MissingAthSendsAUserInfoProofWithoutAth()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);

        using var response = await SignInFlow.PostFormAsync(client, "/Account/UserInfo", WithFault(Fault.MissingAth));

        var userInfo = factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint).Last();
        Assert.StartsWith("DPoP ", userInfo.Header("Authorization"));
        await DPoPProof.ValidateAsync(userInfo.Header("DPoP"), "GET", StubIdentify.UserInfoEndpoint, accessToken: null);
    }

    [Fact]
    public async Task ReplayDPoPProofSendsTheSameProofTwice()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);
        factory.Identify.UserInfoResponder = recorded => factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint).Count > 2
            ? StubIdentify.OAuthError(HttpStatusCode.BadRequest, "invalid_token", "The specified access token is not valid.")
            : factory.Identify.DefaultUserInfoResponse(recorded);

        using var response = await SignInFlow.PostFormAsync(client, "/Account/UserInfo", WithFault(Fault.ReplayDPoPProof));
        var page = await client.GetStringAsync("/");

        var requests = factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint);
        Assert.Equal(3, requests.Count);
        Assert.Equal(requests[1].Header("DPoP"), requests[2].Header("DPoP"));
        Assert.Contains("The UserInfo endpoint returned HTTP 400: invalid_token", page);
    }

    [Fact]
    public async Task NewDPoPKeyOnRefreshBindsTheNewAccessTokenToANewKey()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);
        var request = await SignInFlow.SignInAsync(client, factory);

        using var response = await SignInFlow.PostFormAsync(client, "/Account/Refresh", WithFault(Fault.NewDPoPKeyOnRefresh));
        var page = await client.GetStringAsync("/");

        var refreshProof = DPoPProof.Read(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint).Last().Header("DPoP")!);
        Assert.NotEqual(request.Parameters["dpop_jkt"], refreshProof.Thumbprint);
        Assert.Contains($"Thumbprint of the DPoP key of the sign-in</td><td><code>{refreshProof.Thumbprint}", page);
        Assert.Contains("Bound to the key of the sign-in</td><td><strong>Yes", page);

        using var userInfoResponse = await SignInFlow.PostFormAsync(client, "/Account/UserInfo");
        var userInfoProof = DPoPProof.Read(factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint).Last().Header("DPoP")!);
        Assert.Equal(refreshProof.Thumbprint, userInfoProof.Thumbprint);
    }
}
