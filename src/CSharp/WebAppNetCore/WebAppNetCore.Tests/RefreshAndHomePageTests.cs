using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using Xunit;

namespace WebAppNetCore.Tests;

public sealed class RefreshAndHomePageTests
{
    private static Dictionary<string, string?> DPoPWithPar() => new()
    {
        ["OpenIdConnectOptions:PushedAuthorization"] = "Require",
        ["OpenIdConnectOptions:DPoP:BindAccessTokens"] = "true",
        ["OpenIdConnectOptions:DPoP:SendDPoPJkt"] = "true"
    };

    [Fact]
    public async Task RefreshUsesTheDPoPKeyOfTheSignInAndKeepsTheRefreshToken()
    {
        using var factory = new TestWebApplicationFactory(settings: DPoPWithPar());
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);
        var before = await TestSession.GetAsync(client);

        var page = await RefreshAsync(client);

        Assert.Contains("The refresh succeeded. The refresh token is unchanged.", page);
        var tokenRequests = factory.Identify.RequestsTo(StubIdentify.TokenEndpoint);
        Assert.Equal(2, tokenRequests.Count);
        Assert.Equal("refresh_token", tokenRequests[1].Form["grant_type"]);
        Assert.Equal(StubIdentify.RefreshToken, tokenRequests[1].Form["refresh_token"]);
        Assert.Equal(TestWebApplicationFactory.ClientSecret, tokenRequests[1].Form["client_secret"]);
        var codeProof = DPoPProof.Read(tokenRequests[0].Header("DPoP")!);
        var refreshProof = await DPoPProof.ValidateAsync(tokenRequests[1].Header("DPoP"), "POST", StubIdentify.TokenEndpoint);
        Assert.Equal(codeProof.Thumbprint, refreshProof.Thumbprint);

        var after = await TestSession.GetAsync(client);
        Assert.NotEqual(before.Tokens["access_token"], after.Tokens["access_token"]);
        Assert.Equal(before.Tokens["id_token"], after.Tokens["id_token"]);
        Assert.Equal(StubIdentify.RefreshToken, after.Tokens["refresh_token"]);
        Assert.Equal("DPoP", after.Tokens["token_type"]);
        Assert.Contains("Bound to the key of the sign-in</td><td><strong>Yes", page);
    }

    [Fact]
    public async Task RefreshKeepsTheOldRefreshTokenWhenTheResponseHasNone()
    {
        using var factory = new TestWebApplicationFactory();
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);
        factory.Identify.TokenResponder = _ => StubIdentify.Json(HttpStatusCode.OK, new Dictionary<string, object>
        {
            ["access_token"] = factory.Identify.IssueAccessToken(),
            ["token_type"] = "Bearer",
            ["expires_in"] = 300
        });

        await RefreshAsync(client);

        Assert.Equal(StubIdentify.RefreshToken, (await TestSession.GetAsync(client)).Tokens["refresh_token"]);
    }

    [Fact]
    public async Task RefreshStoresAReplacementRefreshToken()
    {
        using var factory = new TestWebApplicationFactory();
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);
        factory.Identify.TokenResponder = _ => StubIdentify.Json(HttpStatusCode.OK, new Dictionary<string, object>
        {
            ["access_token"] = factory.Identify.IssueAccessToken(),
            ["token_type"] = "Bearer",
            ["refresh_token"] = "refresh-token-2"
        });

        var page = await RefreshAsync(client);

        Assert.Contains("Identify returned a new refresh token, and the sample stored it.", page);
        Assert.Equal("refresh-token-2", (await TestSession.GetAsync(client)).Tokens["refresh_token"]);
    }

    [Fact]
    public async Task ARefreshErrorIsShownOnTheHomePage()
    {
        using var factory = new TestWebApplicationFactory();
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);
        factory.Identify.TokenResponder = _ => StubIdentify.OAuthError(HttpStatusCode.BadRequest, "invalid_grant", "The refresh token is not valid.");

        var page = await RefreshAsync(client);

        Assert.Contains("The token endpoint returned HTTP 400: invalid_grant (The refresh token is not valid.)", page);
    }

    [Fact]
    public async Task RefreshWithoutARefreshTokenExplainsTheSetting()
    {
        using var factory = new TestWebApplicationFactory();
        factory.Identify.TokenResponder = recorded => StubIdentify.Json(HttpStatusCode.OK, new Dictionary<string, object>
        {
            ["access_token"] = factory.Identify.IssueAccessToken(),
            ["token_type"] = "Bearer",
            ["id_token"] = factory.Identify.IssueIdToken(factory.Identify.Nonce)
        });
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);

        var page = await RefreshAsync(client);

        Assert.Contains("AllowRefreshToken=true", page);
        Assert.Single(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint));
    }

    [Fact]
    public async Task TheUserInfoButtonCallsUserInfoWithAFreshProof()
    {
        using var factory = new TestWebApplicationFactory(settings: DPoPWithPar());
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);

        using var response = await SignInFlow.PostFormAsync(client, "/Account/UserInfo");
        Assert.Equal("/", response.Headers.Location!.OriginalString);
        var page = await client.GetStringAsync("/");

        Assert.Contains("The UserInfo request succeeded.", page);
        Assert.Contains("user@provider.test", page);
        var userInfoRequests = factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint);
        Assert.Equal(2, userInfoRequests.Count);
        var accessToken = (await TestSession.GetAsync(client)).Tokens["access_token"];
        var first = DPoPProof.Read(userInfoRequests[0].Header("DPoP")!);
        var second = await DPoPProof.ValidateAsync(userInfoRequests[1].Header("DPoP"), "GET", StubIdentify.UserInfoEndpoint, accessToken);
        Assert.NotEqual(first.Jti, second.Jti);
    }

    [Fact]
    public async Task AUserInfoErrorIsShownOnTheHomePage()
    {
        using var factory = new TestWebApplicationFactory(settings: DPoPWithPar());
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);
        factory.Identify.UserInfoResponder = _ => StubIdentify.OAuthError(HttpStatusCode.BadRequest, "invalid_token", "The specified access token is not valid.");

        using var response = await SignInFlow.PostFormAsync(client, "/Account/UserInfo");
        var page = await client.GetStringAsync("/");

        Assert.Contains("The UserInfo endpoint returned HTTP 400: invalid_token (The specified access token is not valid.)", page);
    }

    [Fact]
    public async Task TheHomePageShowsTheProtocolStateWithoutSecrets()
    {
        using var factory = new TestWebApplicationFactory(settings: DPoPWithPar());
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);

        var page = await client.GetStringAsync("/");

        Assert.Contains("Pushed authorization requests (PushedAuthorization)</td><td><code>Require", page);
        Assert.Contains(StubIdentify.RequestUri, page);
        Assert.Contains("Pushed authorization request: HTTP 201", page);
        Assert.Contains("Authorization response: iss check passed (RFC 9207)", page);
        Assert.Contains("Token request (authorization code): HTTP 200: token_type=DPoP", page);
        Assert.Contains("UserInfo request: HTTP 200", page);
        Assert.Contains("\"typ\": \"dpop+jwt\"", WebUtility.HtmlDecode(page));
        Assert.DoesNotContain(TestWebApplicationFactory.ClientSecret, page);
        var codeVerifier = factory.Identify.RequestsTo(StubIdentify.TokenEndpoint).Single().Form["code_verifier"];
        Assert.DoesNotContain(codeVerifier, page);
    }

    [Fact]
    public async Task TheHomePageShowsTheBuildingBlocksAndWarningsToAnonymousUsers()
    {
        using var factory = new TestWebApplicationFactory(settings: new Dictionary<string, string?>
        {
            ["OpenIdConnectOptions:DPoP:SendDPoPJkt"] = "true"
        });
        using var client = SignInFlow.CreateHttpsClient(factory);

        var page = await client.GetStringAsync("/");

        Assert.Contains("DPoP code binding with dpop_jkt (DPoP:SendDPoPJkt)</td><td><code>True", page);
        Assert.Contains("but DPoP:BindAccessTokens is false", page);
        Assert.DoesNotContain("Protocol trace", page);
    }

    [Fact]
    public async Task ALostSessionStateIsExplainedWhenDPoPNeedsTheKey()
    {
        using var factory = new TestWebApplicationFactory(settings: DPoPWithPar());
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);
        // As after a restart of the application.
        ((MemoryCache)factory.Services.GetRequiredService<IMemoryCache>()).Compact(1.0);

        using var response = await SignInFlow.PostFormAsync(client, "/Account/UserInfo");
        var page = await client.GetStringAsync("/");

        Assert.Contains("the key of this sign-in is no longer available", page);
        Assert.Contains("The server-side state of this sign-in is gone", page);
        Assert.Single(factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint));
    }

    private static async Task<string> RefreshAsync(HttpClient client)
    {
        using var response = await SignInFlow.PostFormAsync(client, "/Account/Refresh");
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/", response.Headers.Location!.OriginalString);
        return await client.GetStringAsync("/");
    }
}
