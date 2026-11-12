using System.Net;
using System.Net.Http.Headers;
using WebAppNetCore.OAuth;
using Xunit;

namespace WebAppNetCore.Tests;

/// <summary>
/// The faults of the scheme and the place of the access token at UserInfo, the client authentication at revocation, the
/// password grant, and the refresh of a public client without a proof. Each test checks the outgoing request at the stub Identify.
/// </summary>
public sealed class TokenTransportFaultTests
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

    private static RecordedRequest Single(TestWebApplicationFactory factory, string endpoint) => Assert.Single(factory.Identify.RequestsTo(endpoint));

    private static async Task<string> HomePageAsync(HttpClient client) => WebUtility.HtmlDecode(await client.GetStringAsync("/"));

    /// <summary>A UserInfo rejection as RFC 9449 section 7.1 describes it: HTTP 401 with a DPoP challenge and no body.</summary>
    private static HttpResponseMessage DPoPChallenge(string error)
    {
        var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
        response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue("DPoP", $"error=\"{error}\", algs=\"PS256\""));
        return response;
    }

    [Fact]
    public async Task DPoPSchemeForBearerTokenSendsTheBearerTokenWithTheDPoPSchemeAndAProofOfANewKey()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings());
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);
        var session = await TestSession.GetAsync(client);
        Assert.Equal("Bearer", session.Tokens["token_type"]);
        var accessToken = session.Tokens["access_token"];
        factory.Identify.UserInfoResponder = _ => DPoPChallenge("invalid_token");

        using var response = await SignInFlow.PostFormAsync(client, "/Account/UserInfo", WithFault(Fault.DPoPSchemeForBearerToken));
        var page = await HomePageAsync(client);

        var userInfo = factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint).Last();
        Assert.Equal(HttpMethod.Get, userInfo.Method);
        Assert.Equal("DPoP " + accessToken, userInfo.Header("Authorization"));
        await DPoPProof.ValidateAsync(userInfo.Header("DPoP"), "GET", StubIdentify.UserInfoEndpoint, accessToken);
        Assert.Contains("The UserInfo endpoint returned HTTP 401: invalid_token", page);
        Assert.Contains("DPoP error=\"invalid_token\", algs=\"PS256\"", page);
    }

    [Fact]
    public async Task DPoPSchemeForBearerTokenNeedsATokenWithoutTheBinding()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);

        using var response = await SignInFlow.PostFormAsync(client, "/Account/UserInfo", WithFault(Fault.DPoPSchemeForBearerToken));

        Assert.Contains("The fault DPoPSchemeForBearerToken needs an access token that is not bound to a DPoP key", await HomePageAsync(client));
        // Only the UserInfo request of the sign-in.
        Single(factory, StubIdentify.UserInfoEndpoint);
    }

    [Fact]
    public async Task AccessTokenInFormSendsTheTokenInTheFormOfAPostWithAProof()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);
        var request = await SignInFlow.SignInAsync(client, factory);
        var accessToken = (await TestSession.GetAsync(client)).Tokens["access_token"];
        factory.Identify.UserInfoResponder = _ => DPoPChallenge("invalid_token");

        using var response = await SignInFlow.PostFormAsync(client, "/Account/UserInfo", WithFault(Fault.AccessTokenInForm));
        var page = await HomePageAsync(client);

        var userInfo = factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint).Last();
        Assert.Equal(HttpMethod.Post, userInfo.Method);
        Assert.Null(userInfo.Header("Authorization"));
        Assert.StartsWith("application/x-www-form-urlencoded", userInfo.Header("Content-Type"));
        Assert.Equal(accessToken, Assert.Single(userInfo.Form).Value);
        Assert.Equal("access_token", userInfo.Form.Keys.Single());
        var proof = await DPoPProof.ValidateAsync(userInfo.Header("DPoP"), "POST", StubIdentify.UserInfoEndpoint, accessToken);
        Assert.Equal(request.Parameters["dpop_jkt"], proof.Thumbprint);
        Assert.Contains("The UserInfo endpoint returned HTTP 401: invalid_token", page);
        // The trace shows that the form has the token, not the token.
        Assert.Contains("<td>Form access_token</td><td><pre>(present)</pre></td>", page);
    }

    [Fact]
    public async Task DPoPSchemeWithoutProofSendsTheDPoPSchemeWithoutADPoPHeader()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);
        var accessToken = (await TestSession.GetAsync(client)).Tokens["access_token"];
        factory.Identify.UserInfoResponder = _ => DPoPChallenge("invalid_dpop_proof");

        using var response = await SignInFlow.PostFormAsync(client, "/Account/UserInfo", WithFault(Fault.DPoPSchemeWithoutProof));

        var userInfo = factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint).Last();
        Assert.Equal(HttpMethod.Get, userInfo.Method);
        Assert.Equal("DPoP " + accessToken, userInfo.Header("Authorization"));
        Assert.Null(userInfo.Header("DPoP"));
        Assert.Contains("The UserInfo endpoint returned HTTP 401: invalid_dpop_proof", await HomePageAsync(client));
    }

    [Theory]
    [InlineData(Fault.AccessTokenInForm)]
    [InlineData(Fault.DPoPSchemeWithoutProof)]
    public async Task TheBoundTokenFaultsNeedADPoPBoundToken(Fault fault)
    {
        using var factory = new TestWebApplicationFactory(settings: Settings());
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);

        using var response = await SignInFlow.PostFormAsync(client, "/Account/UserInfo", WithFault(fault));

        Assert.Contains($"The fault {fault} needs a DPoP-bound access token", await HomePageAsync(client));
        Single(factory, StubIdentify.UserInfoEndpoint);
    }

    [Fact]
    public async Task RevokeWithClientSecretUsesTheSecretInsteadOfTheAssertion()
    {
        using var certificate = new TestCertificateFile();
        var settings = Settings(dpop: true, par: true);
        foreach (var setting in certificate.PrivateKeyJwtSettings())
        {
            settings[setting.Key] = setting.Value;
        }

        using var factory = new TestWebApplicationFactory(settings: settings);
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);
        var accessToken = (await TestSession.GetAsync(client)).Tokens["access_token"];
        factory.Identify.RevocationResponder = _ => StubIdentify.OAuthError(HttpStatusCode.Unauthorized, "invalid_client", "Client authentication failed.");

        using var response = await SignInFlow.PostFormAsync(client, "/Account/Revoke", WithFault(Fault.RevokeWithClientSecret));

        var form = Single(factory, StubIdentify.RevocationEndpoint).Form;
        Assert.Equal(accessToken, form["token"]);
        Assert.Equal(TestWebApplicationFactory.ClientId, form["client_id"]);
        Assert.Equal(TestWebApplicationFactory.ClientSecret, form["client_secret"]);
        Assert.False(form.ContainsKey("client_assertion"), "The revocation request has a client assertion.");
        Assert.Contains("The revocation endpoint returned HTTP 401: invalid_client", await HomePageAsync(client));
    }

    [Fact]
    public async Task RevocationWithoutAFaultUsesTheConfiguredClientAuthentication()
    {
        using var certificate = new TestCertificateFile();
        var settings = Settings(dpop: true, par: true);
        foreach (var setting in certificate.PrivateKeyJwtSettings())
        {
            settings[setting.Key] = setting.Value;
        }

        using var factory = new TestWebApplicationFactory(settings: settings);
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);

        using var response = await SignInFlow.PostFormAsync(client, "/Account/Revoke");

        var form = Single(factory, StubIdentify.RevocationEndpoint).Form;
        Assert.False(form.ContainsKey("client_secret"), "The revocation request has the client secret.");
        await CodeFlowTests.ValidateClientAssertionAsync(form["client_assertion"], certificate);
    }

    [Fact]
    public async Task PasswordGrantSendsAPasswordGrantWithAnUnknownUserAndARandomPassword()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);
        factory.Identify.TokenResponder = _ => StubIdentify.OAuthError(HttpStatusCode.BadRequest, "unauthorized_client", "The grant type is not allowed.");

        using var first = await SignInFlow.PostFormAsync(client, "/Account/ClientCredentials", WithFault(Fault.PasswordGrant));
        var page = await HomePageAsync(client);
        using var second = await SignInFlow.PostFormAsync(client, "/Account/ClientCredentials", WithFault(Fault.PasswordGrant));

        var requests = factory.Identify.RequestsTo(StubIdentify.TokenEndpoint);
        Assert.Equal(2, requests.Count);
        foreach (var token in requests)
        {
            Assert.Equal("password", token.Form["grant_type"]);
            Assert.Equal(TokenClient.PasswordGrantUserName, token.Form["username"]);
            Assert.Equal(43, token.Form["password"].Length);
            Assert.Equal(TestWebApplicationFactory.ClientSecret, token.Form["client_secret"]);
            await DPoPProof.ValidateAsync(token.Header("DPoP"), "POST", StubIdentify.TokenEndpoint);
        }

        Assert.NotEqual(requests[0].Form["password"], requests[1].Form["password"]);
        Assert.Contains("The token endpoint returned HTTP 400: unauthorized_client", page);
        Assert.Empty(factory.Identify.RequestsTo(StubIdentify.ParEndpoint));
    }

    [Fact]
    public async Task APasswordGrantThatSucceedsIsNamedInTheResult()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);

        using var response = await SignInFlow.PostFormAsync(client, "/Account/ClientCredentials", WithFault(Fault.PasswordGrant));

        Assert.Contains("The password grant request succeeded: token_type DPoP", await HomePageAsync(client));
    }

    [Fact]
    public async Task NoDPoPProofOnRefreshOfAPublicClientSendsOnlyTheClientIdAndTheRefreshToken()
    {
        var settings = Settings(dpop: true, par: true);
        settings["OpenIdConnectOptions:TokenAuthnMethod"] = "none";
        using var factory = new TestWebApplicationFactory(settings: settings);
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);

        using var response = await SignInFlow.PostFormAsync(client, "/Account/Refresh", WithFault(Fault.NoDPoPProof));

        var refresh = factory.Identify.RequestsTo(StubIdentify.TokenEndpoint).Last();
        Assert.Equal(
            new[] { "client_id", "grant_type", "refresh_token" },
            refresh.Form.Keys.OrderBy(k => k, StringComparer.Ordinal));
        Assert.Equal(TestWebApplicationFactory.ClientId, refresh.Form["client_id"]);
        Assert.Equal(StubIdentify.RefreshToken, refresh.Form["refresh_token"]);
        Assert.Null(refresh.Header("DPoP"));
        Assert.Null(refresh.Header("Authorization"));
    }

    [Fact]
    public async Task TheNewFaultListsAreShownWhenFaultInjectionIsOn()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);

        var anonymousPage = await client.GetStringAsync("/");
        Assert.Contains("value=\"PasswordGrant\"", anonymousPage);
        Assert.DoesNotContain("value=\"RevokeWithClientSecret\"", anonymousPage);

        await SignInFlow.SignInAsync(client, factory);
        var page = await client.GetStringAsync("/");
        foreach (var fault in new[] { Fault.DPoPSchemeForBearerToken, Fault.AccessTokenInForm, Fault.DPoPSchemeWithoutProof, Fault.RevokeWithClientSecret })
        {
            Assert.Contains($"value=\"{fault}\"", page);
        }
    }

    [Fact]
    public async Task TheNewFaultsAreIgnoredWhenFaultInjectionIsOff()
    {
        var settings = Settings(dpop: true);
        settings["Testing:EnableFaultInjection"] = "false";
        using var factory = new TestWebApplicationFactory(settings: settings);
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);
        var accessToken = (await TestSession.GetAsync(client)).Tokens["access_token"];

        using var userInfoResponse = await SignInFlow.PostFormAsync(client, "/Account/UserInfo", WithFault(Fault.AccessTokenInForm));
        using var grantResponse = await SignInFlow.PostFormAsync(client, "/Account/ClientCredentials", WithFault(Fault.PasswordGrant));

        var userInfo = factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint).Last();
        Assert.Equal("DPoP " + accessToken, userInfo.Header("Authorization"));
        Assert.Equal("client_credentials", factory.Identify.RequestsTo(StubIdentify.TokenEndpoint).Last().Form["grant_type"]);
    }
}
