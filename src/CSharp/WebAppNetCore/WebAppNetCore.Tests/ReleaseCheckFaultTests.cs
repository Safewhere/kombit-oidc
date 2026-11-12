using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System.Net;
using WebAppNetCore.OAuth;
using Xunit;

namespace WebAppNetCore.Tests;

/// <summary>
/// The faults and test settings that the US38481 release check of FAPI 2.0 added: a browser scope that the pushed request does not
/// have, a nonce of 64 characters, the client checks of the ID token nonce and of the authorization response issuer, an unbound
/// access token in the form of a UserInfo request, a client credentials request without a proof, and a session that outlives the
/// access token.
/// </summary>
public sealed class ReleaseCheckFaultTests
{
    private static Dictionary<string, string?> Settings(bool dpop = false, bool par = false)
    {
        var settings = new Dictionary<string, string?>
        {
            ["Testing:EnableFaultInjection"] = "true"
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

    private static async Task<string> HomePageAsync(HttpClient client) => WebUtility.HtmlDecode(await client.GetStringAsync("/"));

    private static OpenIdConnectOptions ConnectOptions(TestWebApplicationFactory factory) =>
        factory.Services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get(OpenIdConnectDefaults.AuthenticationScheme);

    [Fact]
    public async Task ExtraBrowserScopeNotPushedAddsAScopeThatThePushedRequestDoesNotHave()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(par: true));
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.StartAsync(client, factory, WithFault(Fault.ExtraBrowserScopeNotPushed));

        Assert.Equal(new[] { "client_id", "request_uri", "scope" }, request.BrowserParameters.Keys.OrderBy(k => k));
        Assert.Equal("openid " + TokenClient.NotGrantedScope, request.BrowserParameters["scope"]);
        var push = Assert.Single(factory.Identify.RequestsTo(StubIdentify.ParEndpoint));
        Assert.Equal("openid", push.Form["scope"]);
    }

    [Fact]
    public async Task NonceLengthSixtyFourSendsANonceOfSixtyFourCharacters()
    {
        var settings = Settings();
        settings["Testing:NonceLength"] = "64";
        using var factory = new TestWebApplicationFactory(settings: settings);
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.StartAsync(client, factory);
        using var callback = await SignInFlow.CompleteAsync(client, factory, request);

        Assert.Matches("^[A-Za-z0-9_-]{64}$", request.Parameters["nonce"]);
        await SignInFlow.AssertSignedInAsync(client, callback);
    }

    [Fact]
    public async Task NonceLengthIsIgnoredWithoutFaultInjection()
    {
        using var factory = new TestWebApplicationFactory(settings: new Dictionary<string, string?> { ["Testing:NonceLength"] = "64" });
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.StartAsync(client, factory);

        Assert.Matches("^[A-Za-z0-9_-]{43}$", request.Parameters["nonce"]);
    }

    [Theory]
    [InlineData("42")]
    [InlineData("65")]
    [InlineData("long")]
    public void ANonceLengthOutsideTheRangeStopsTheApplication(string value)
    {
        var settings = Settings();
        settings["Testing:NonceLength"] = value;
        using var factory = new TestWebApplicationFactory(settings: settings);

        var exception = Assert.ThrowsAny<Exception>(() => factory.CreateClient());

        Assert.Contains($"'Testing:NonceLength' has the invalid value '{value}'", exception.ToString());
    }

    [Fact]
    public async Task IdTokenNonceMismatchSendsAnotherNonceAndTheSampleRejectsTheIdToken()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings());
        using var client = SignInFlow.CreateHttpsClient(factory);
        var request = await SignInFlow.StartAsync(client, factory, WithFault(Fault.IdTokenNonceMismatch));

        // The stub returns the nonce of the authorization request, which is not the nonce of the nonce cookie.
        using var callback = await SignInFlow.CompleteAsync(client, factory, request);

        var errorPage = await SignInFlow.AssertErrorPageAsync(client, callback);
        Assert.Contains("nonce", errorPage, StringComparison.OrdinalIgnoreCase);
        Assert.Matches("^[A-Za-z0-9_-]{43}$", request.Parameters["nonce"]);
    }

    [Fact]
    public async Task AuthorizationResponseIssMismatchStopsTheSignInBeforeTheCodeIsRedeemed()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings());
        using var client = SignInFlow.CreateHttpsClient(factory);
        var request = await SignInFlow.StartAsync(client, factory, WithFault(Fault.AuthorizationResponseIssMismatch));

        using var callback = await SignInFlow.CompleteAsync(client, factory, request);

        var errorPage = await SignInFlow.AssertErrorPageAsync(client, callback);
        Assert.Equal(
            $"The iss parameter 'https://fault.invalid/runtime/oauth2' of the authorization response is not the issuer '{StubIdentify.Issuer}' (RFC 9207).",
            SignInFlow.ErrorMessage(errorPage));
        Assert.Empty(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint));
    }

    [Fact]
    public async Task AuthorizationResponseIssMissingStopsTheSignInWhenDiscoveryAdvertisesTheParameter()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings()) { AdvertiseIssuerParameter = true };
        using var client = SignInFlow.CreateHttpsClient(factory);
        var request = await SignInFlow.StartAsync(client, factory, WithFault(Fault.AuthorizationResponseIssMissing));

        using var callback = await SignInFlow.CompleteAsync(client, factory, request);

        var errorPage = await SignInFlow.AssertErrorPageAsync(client, callback);
        Assert.Contains("has no iss parameter", SignInFlow.ErrorMessage(errorPage));
        Assert.Empty(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint));
    }

    [Fact]
    public async Task BearerTokenInFormSendsTheUnboundTokenInTheFormWithoutAProof()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings());
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);
        var accessToken = (await TestSession.GetAsync(client)).Tokens["access_token"];

        using var response = await SignInFlow.PostFormAsync(client, "/Account/UserInfo", WithFault(Fault.BearerTokenInForm));
        var page = await HomePageAsync(client);

        var userInfo = factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint).Last();
        Assert.Equal(HttpMethod.Post, userInfo.Method);
        Assert.Null(userInfo.Header("Authorization"));
        Assert.Null(userInfo.Header("DPoP"));
        Assert.Equal(accessToken, Assert.Single(userInfo.Form).Value);
        Assert.DoesNotContain("The UserInfo endpoint returned", page);
    }

    [Fact]
    public async Task BearerTokenInFormNeedsATokenWithoutTheBinding()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);
        var userInfoRequests = factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint).Count();

        using var response = await SignInFlow.PostFormAsync(client, "/Account/UserInfo", WithFault(Fault.BearerTokenInForm));
        var page = await HomePageAsync(client);

        Assert.Contains("The fault BearerTokenInForm needs an access token that is not bound to a DPoP key", page);
        Assert.Equal(userInfoRequests, factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint).Count());
    }

    [Fact]
    public async Task NoDPoPProofSendsTheClientCredentialsRequestWithoutAProof()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);

        using var response = await SignInFlow.PostFormAsync(client, "/Account/ClientCredentials", WithFault(Fault.NoDPoPProof));

        var token = Assert.Single(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint));
        Assert.Equal("client_credentials", token.Form["grant_type"]);
        Assert.Null(token.Header("DPoP"));
    }

    [Fact]
    public async Task NoDPoPProofAtClientCredentialsNeedsDPoP()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings());
        using var client = SignInFlow.CreateHttpsClient(factory);

        using var response = await SignInFlow.PostFormAsync(client, "/Account/ClientCredentials", WithFault(Fault.NoDPoPProof));
        var page = await HomePageAsync(client);

        Assert.Contains("The fault NoDPoPProof needs DPoP:BindAccessTokens=true.", page);
        Assert.Empty(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint));
    }

    [Theory]
    [InlineData("true", "true", false)]
    [InlineData("true", "false", true)]
    [InlineData("false", "true", true)]
    public void KeepSessionAfterTokenExpiryNeedsFaultInjection(string enableFaultInjection, string keepSession, bool useTokenLifetime)
    {
        using var factory = new TestWebApplicationFactory(settings: new Dictionary<string, string?>
        {
            ["Testing:EnableFaultInjection"] = enableFaultInjection,
            ["Testing:KeepSessionAfterTokenExpiry"] = keepSession
        });
        using var client = factory.CreateClient();

        Assert.Equal(useTokenLifetime, ConnectOptions(factory).UseTokenLifetime);
    }
}
