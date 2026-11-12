using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using WebAppNetCore.OAuth;
using Xunit;

namespace WebAppNetCore.Tests;

public sealed class PushedAuthorizationTests
{
    private static Dictionary<string, string?> Par(string behavior = "Require") => new()
    {
        ["OpenIdConnectOptions:PushedAuthorization"] = behavior
    };

    [Fact]
    public async Task ThePushedRequestHasTheAuthorizationParametersAndTheBrowserGetsOnlyClientIdAndRequestUri()
    {
        using var factory = new TestWebApplicationFactory(settings: Par());
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.StartAsync(client, factory, new Dictionary<string, string>
        {
            ["loa"] = "loa-3",
            ["max_age"] = "600",
            ["forceLogin"] = "true"
        });

        Assert.Equal(new[] { "client_id", "request_uri" }, request.BrowserParameters.Keys.OrderBy(k => k));
        Assert.Equal(TestWebApplicationFactory.ClientId, request.BrowserParameters["client_id"]);
        Assert.Equal(StubIdentify.RequestUri, request.BrowserParameters["request_uri"]);

        var par = Assert.Single(factory.Identify.RequestsTo(StubIdentify.ParEndpoint));
        Assert.Equal(HttpMethod.Post, par.Method);
        Assert.Equal("code", par.Form["response_type"]);
        Assert.Equal(TestWebApplicationFactory.ClientId, par.Form["client_id"]);
        Assert.Equal(TestWebApplicationFactory.ClientSecret, par.Form["client_secret"]);
        Assert.Equal("https://localhost/signin-oidc", par.Form["redirect_uri"]);
        Assert.Equal("openid", par.Form["scope"]);
        Assert.Equal("S256", par.Form["code_challenge_method"]);
        Assert.Equal("loa-3", par.Form["acr_values"]);
        Assert.Equal("600", par.Form["max_age"]);
        Assert.Equal("login", par.Form["prompt"]);
        Assert.False(string.IsNullOrEmpty(par.Form["code_challenge"]));
        Assert.False(string.IsNullOrEmpty(par.Form["state"]));
        Assert.False(string.IsNullOrEmpty(par.Form["nonce"]));
        Assert.False(par.Form.ContainsKey("request_uri"));
    }

    [Fact]
    public async Task APushedSignInCompletes()
    {
        using var factory = new TestWebApplicationFactory(settings: Par());
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.SignInAsync(client, factory);

        var tokenRequest = Assert.Single(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint));
        Assert.Equal(request.Parameters["code_challenge"], CodeFlowTests.CodeChallenge(tokenRequest.Form["code_verifier"]));
    }

    [Fact]
    public async Task ThePostAuthorizationMethodSendsOnlyClientIdAndRequestUri()
    {
        using var factory = new TestWebApplicationFactory("POST", Par());
        using var client = SignInFlow.CreateHttpsClient(factory);

        using var response = await SignInFlow.PostSignInAsync(client);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains($"action=\"{StubIdentify.AuthorizationEndpoint}\"", body);
        Assert.Equal(TestWebApplicationFactory.ClientId, SignInFlow.ReadFormValue(body, "client_id"));
        Assert.Equal(StubIdentify.RequestUri, SignInFlow.ReadFormValue(body, "request_uri"));
        Assert.Equal(2, System.Text.RegularExpressions.Regex.Matches(body, "<input type=\"hidden\"").Count);
    }

    [Fact]
    public async Task TheHandleOfTheSignInIsInTheStateOfThePushedRequest()
    {
        using var factory = new TestWebApplicationFactory(settings: Par());
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.StartAsync(client, factory);

        // The handler protects the properties into state before it pushes, so an item that OnRedirectToIdentityProvider sets is
        // in the pushed state and comes back with the authorization response.
        var options = factory.Services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get(OpenIdConnectDefaults.AuthenticationScheme);
        var properties = options.StateDataFormat.Unprotect(request.Parameters["state"])!;
        Assert.False(string.IsNullOrEmpty(properties.Items[ClientSessionStore.HandleKey]));
        Assert.NotNull(factory.Services.GetRequiredService<ClientSessionStore>().Get(properties)?.PushedAuthorization);
    }

    [Fact]
    public async Task ClientSecretBasicAuthenticatesThePushedRequestInTheHeader()
    {
        var settings = Par();
        settings["OpenIdConnectOptions:TokenAuthnMethod"] = "client_secret_basic";
        using var factory = new TestWebApplicationFactory(settings: settings);
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInFlow.StartAsync(client, factory);

        var par = Assert.Single(factory.Identify.RequestsTo(StubIdentify.ParEndpoint));
        var authorization = AuthenticationHeaderValue.Parse(par.Header("Authorization")!);
        Assert.Equal("Basic", authorization.Scheme);
        Assert.Equal(
            $"{TestWebApplicationFactory.ClientId}:{TestWebApplicationFactory.ClientSecret}",
            Encoding.UTF8.GetString(Convert.FromBase64String(authorization.Parameter!)));
        Assert.False(par.Form.ContainsKey("client_secret"));
    }

    [Theory]
    [InlineData("TokenEndpoint", StubIdentify.TokenEndpoint)]
    [InlineData("Issuer", StubIdentify.Issuer)]
    public async Task PrivateKeyJwtAuthenticatesThePushedRequestWithTheConfiguredAudience(string audience, string expectedAudience)
    {
        using var certificate = new TestCertificateFile();
        var settings = certificate.PrivateKeyJwtSettings();
        settings["OpenIdConnectOptions:PushedAuthorization"] = "Require";
        settings["OpenIdConnectOptions:ClientAssertion:Audience"] = audience;
        using var factory = new TestWebApplicationFactory(settings: settings);
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInFlow.SignInAsync(client, factory);

        var par = Assert.Single(factory.Identify.RequestsTo(StubIdentify.ParEndpoint));
        var token = Assert.Single(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint));
        var parAssertion = await CodeFlowTests.ValidateClientAssertionAsync(par.Form["client_assertion"], certificate);
        var tokenAssertion = await CodeFlowTests.ValidateClientAssertionAsync(token.Form["client_assertion"], certificate);
        Assert.Equal(expectedAudience, parAssertion.GetPayloadValue<string>("aud"));
        Assert.Equal(expectedAudience, tokenAssertion.GetPayloadValue<string>("aud"));
        Assert.NotEqual(parAssertion.Id, tokenAssertion.Id);
    }

    [Fact]
    public async Task APushedAuthorizationErrorIsShownOnTheErrorPage()
    {
        using var factory = new TestWebApplicationFactory(settings: Par());
        factory.Identify.ParResponder = _ => StubIdentify.OAuthError(HttpStatusCode.Unauthorized, "invalid_client", "Client authentication failed.");
        using var client = SignInFlow.CreateHttpsClient(factory);

        using var response = await SignInFlow.PostSignInAsync(client);

        var errorPage = await SignInFlow.AssertErrorPageAsync(client, response);
        Assert.Contains("The PAR endpoint returned HTTP 401: invalid_client (Client authentication failed.)", errorPage);
    }

    [Fact]
    public async Task UseIfAvailablePushesWhenDiscoveryHasAParEndpoint()
    {
        using var factory = new TestWebApplicationFactory(settings: Par("UseIfAvailable"));
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.StartAsync(client, factory);

        Assert.True(request.BrowserParameters.ContainsKey("request_uri"));
    }

    [Fact]
    public async Task UseIfAvailableSendsADirectRequestWhenDiscoveryHasNoParEndpoint()
    {
        using var factory = new TestWebApplicationFactory(settings: Par("UseIfAvailable")) { PublishParEndpoint = false };
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.StartAsync(client, factory);

        Assert.False(request.BrowserParameters.ContainsKey("request_uri"));
        Assert.Equal("code", request.BrowserParameters["response_type"]);
        Assert.Empty(factory.Identify.RequestsTo(StubIdentify.ParEndpoint));
    }

    [Fact]
    public async Task RequireWithoutAParEndpointIsShownOnTheErrorPage()
    {
        using var factory = new TestWebApplicationFactory(settings: Par()) { PublishParEndpoint = false };
        using var client = SignInFlow.CreateHttpsClient(factory);

        using var response = await SignInFlow.PostSignInAsync(client);

        var errorPage = await SignInFlow.AssertErrorPageAsync(client, response);
        Assert.Contains("no pushed authorization endpoint is available", errorPage);
    }

    [Fact]
    public async Task TheDirectRequestHasNoTelemetryParameters()
    {
        using var factory = new TestWebApplicationFactory();
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.StartAsync(client, factory);

        Assert.DoesNotContain(request.BrowserParameters.Keys, k => k.StartsWith("x-client-", StringComparison.Ordinal));
        Assert.Empty(factory.Identify.RequestsTo(StubIdentify.ParEndpoint));
    }
}
