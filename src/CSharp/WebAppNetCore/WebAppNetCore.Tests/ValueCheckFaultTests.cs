using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using WebAppNetCore.OAuth;
using Xunit;

namespace WebAppNetCore.Tests;

/// <summary>
/// The faults of values that only a check of the value rejects: a scope that no connection has in the pushed request, a token
/// proof without jwk, client assertions without iss or sub, with a trailing slash in aud, valid for a year, or with another
/// assertion type, code verifiers outside 43 to 128 characters, a token request without redirect_uri, the access token as the
/// refresh token, and the revocation of the refresh token. Each test checks the outgoing request at the stub Identify.
/// </summary>
public sealed class ValueCheckFaultTests
{
    private static Dictionary<string, string?> Settings(bool dpop = false, bool par = true)
    {
        var settings = new Dictionary<string, string?> { ["Testing:EnableFaultInjection"] = "true" };
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

    private static Dictionary<string, string?> PrivateKeyJwtSettings(TestCertificateFile certificate)
    {
        var settings = Settings();
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

    [Fact]
    public async Task ParUnknownScopeAddsAScopeThatNoConnectionHasToThePushedRequest()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings());
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.StartAsync(client, factory, WithFault(Fault.ParUnknownScope));

        Assert.Equal("openid " + TokenClient.NotGrantedScope, request.Parameters["scope"]);
        Assert.Equal(new[] { "client_id", "request_uri" }, request.BrowserParameters.Keys.OrderBy(k => k, StringComparer.Ordinal));
    }

    [Fact]
    public async Task ProofWithoutJwkNamesTheDPoPKeyByKidOnly()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);
        factory.Identify.TokenResponder = _ => StubIdentify.OAuthError(HttpStatusCode.BadRequest, "invalid_dpop_proof", "The DPoP proof has no jwk.");

        var request = await SignInFlow.StartAsync(client, factory, WithFault(Fault.ProofWithoutJwk));
        using var callback = await SignInFlow.CompleteAsync(client, factory, request);

        var proof = Single(factory, StubIdentify.TokenEndpoint).Header("DPoP")!;
        var header = Part(proof, 0);
        var payload = Part(proof, 1);
        Assert.Equal("dpop+jwt", header.GetProperty("typ").GetString());
        Assert.False(header.TryGetProperty("jwk", out _), "The proof header has a jwk.");
        Assert.Equal(request.Parameters["dpop_jkt"], header.GetProperty("kid").GetString());
        Assert.Equal("POST", payload.GetProperty("htm").GetString());
        Assert.Equal(StubIdentify.TokenEndpoint, payload.GetProperty("htu").GetString());
        Assert.False(string.IsNullOrEmpty(payload.GetProperty("jti").GetString()));
        Assert.True(payload.TryGetProperty("iat", out _), "The proof has no iat.");
        Assert.Equal(
            "The token endpoint returned HTTP 400: invalid_dpop_proof (The DPoP proof has no jwk.)",
            SignInFlow.ErrorMessage(await SignInFlow.AssertErrorPageAsync(client, callback)));
    }

    [Theory]
    [InlineData(Fault.AssertionWithoutIss)]
    [InlineData(Fault.AssertionWithoutSub)]
    [InlineData(Fault.AssertionAudienceTrailingSlash)]
    [InlineData(Fault.AssertionLongLived)]
    public async Task AssertionClaimFaultsChangeOnlyTheirClaim(Fault fault)
    {
        using var certificate = new TestCertificateFile();
        using var factory = new TestWebApplicationFactory(settings: PrivateKeyJwtSettings(certificate));
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.StartAsync(client, factory, WithFault(fault));
        using var callback = await SignInFlow.CompleteAsync(client, factory, request);
        await SignInFlow.AssertSignedInAsync(client, callback);

        foreach (var endpoint in new[] { StubIdentify.ParEndpoint, StubIdentify.TokenEndpoint })
        {
            var form = Single(factory, endpoint).Form;
            Assert.Equal(ClientAuthentication.ClientAssertionType, form["client_assertion_type"]);
            Assert.Equal(TestWebApplicationFactory.ClientId, form["client_id"]);
            // Signed with the client key, so that only the changed claim can reject the assertion.
            var assertion = await CodeFlowTests.ValidateClientAssertionAsync(form["client_assertion"], certificate);
            Assert.Equal(fault != Fault.AssertionWithoutIss, assertion.TryGetPayloadValue<string>("iss", out var issuer));
            Assert.Equal(fault != Fault.AssertionWithoutSub, assertion.TryGetPayloadValue<string>("sub", out var subject));
            Assert.Equal(fault == Fault.AssertionWithoutIss ? null : TestWebApplicationFactory.ClientId, issuer);
            Assert.Equal(fault == Fault.AssertionWithoutSub ? null : TestWebApplicationFactory.ClientId, subject);
            Assert.Equal(fault == Fault.AssertionAudienceTrailingSlash ? StubIdentify.Issuer + "/" : StubIdentify.Issuer, Assert.Single(assertion.Audiences));
            Assert.False(string.IsNullOrEmpty(assertion.Id));
            var lifetime = assertion.ValidTo - assertion.IssuedAt;
            Assert.Equal(fault == Fault.AssertionLongLived ? TimeSpan.FromDays(365) : TimeSpan.FromMinutes(5), lifetime);
        }
    }

    [Fact]
    public async Task WrongAssertionTypeSendsAValidAssertionAsASamlAssertion()
    {
        using var certificate = new TestCertificateFile();
        using var factory = new TestWebApplicationFactory(settings: PrivateKeyJwtSettings(certificate));
        using var client = SignInFlow.CreateHttpsClient(factory);
        factory.Identify.ParResponder = _ => StubIdentify.OAuthError(HttpStatusCode.Unauthorized, "invalid_client", "Unsupported client assertion type.");

        using var response = await SignInFlow.PostSignInAsync(client, WithFault(Fault.WrongAssertionType));

        var form = Single(factory, StubIdentify.ParEndpoint).Form;
        Assert.Equal(ClientAuthentication.SamlAssertionType, form["client_assertion_type"]);
        var assertion = await CodeFlowTests.ValidateClientAssertionAsync(form["client_assertion"], certificate);
        Assert.Equal(TestWebApplicationFactory.ClientId, assertion.Issuer);
        Assert.Equal(TestWebApplicationFactory.ClientId, assertion.Subject);
        Assert.Equal(
            "The PAR endpoint returned HTTP 401: invalid_client (Unsupported client assertion type.)",
            SignInFlow.ErrorMessage(await SignInFlow.AssertErrorPageAsync(client, response)));
        Assert.Empty(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint));
    }

    [Theory]
    [InlineData(Fault.ShortCodeVerifier, 42, true)]
    [InlineData(Fault.LongCodeVerifier, 129, true)]
    [InlineData(Fault.ShortCodeVerifier, 42, false)]
    [InlineData(Fault.LongCodeVerifier, 129, false)]
    public async Task CodeVerifierLengthFaultsSendAMatchingPairOfAnotherLength(Fault fault, int length, bool par)
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(par: par));
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.StartAsync(client, factory, WithFault(fault));
        using var callback = await SignInFlow.CompleteAsync(client, factory, request);
        await SignInFlow.AssertSignedInAsync(client, callback);

        var verifier = Single(factory, StubIdentify.TokenEndpoint).Form["code_verifier"];
        Assert.Equal(length, verifier.Length);
        Assert.Matches(new Regex("^[A-Za-z0-9_-]+$"), verifier);
        Assert.Equal("S256", request.Parameters["code_challenge_method"]);
        Assert.Equal(CodeFlowTests.CodeChallenge(verifier), request.Parameters["code_challenge"]);
    }

    [Theory]
    [InlineData(Fault.ShortCodeVerifier)]
    [InlineData(Fault.LongCodeVerifier)]
    public async Task CodeVerifierLengthFaultsNeedPkce(Fault fault)
    {
        var settings = Settings(par: false);
        settings["OpenIdConnectOptions:ResponseType"] = "code id_token";
        using var factory = new TestWebApplicationFactory(settings: settings);
        using var client = SignInFlow.CreateHttpsClient(factory);

        using var response = await SignInFlow.PostSignInAsync(client, WithFault(fault));

        Assert.Equal(
            $"The fault {fault} needs PKCE, which the handler uses with the response type code. The sign-in did not start.",
            SignInFlow.ErrorMessage(await SignInFlow.AssertErrorPageAsync(client, response)));
    }

    [Fact]
    public async Task TokenWithoutRedirectUriOmitsOnlyTheRedirectUri()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings());
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.StartAsync(client, factory, WithFault(Fault.TokenWithoutRedirectUri));
        using var callback = await SignInFlow.CompleteAsync(client, factory, request);
        await SignInFlow.AssertSignedInAsync(client, callback);

        var form = Single(factory, StubIdentify.TokenEndpoint).Form;
        Assert.False(form.ContainsKey("redirect_uri"), "The token request has redirect_uri.");
        Assert.Equal("https://localhost/signin-oidc", request.Parameters["redirect_uri"]);
        Assert.Equal("authorization_code", form["grant_type"]);
        Assert.Equal(SignInFlow.Code, form["code"]);
        Assert.Equal(request.Parameters["code_challenge"], CodeFlowTests.CodeChallenge(form["code_verifier"]));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AccessTokenAsRefreshTokenSendsTheAccessTokenAndKeepsTheTokens(bool accepted)
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true, par: false));
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);
        var tokens = (await TestSession.GetAsync(client)).Tokens;
        if (!accepted)
        {
            factory.Identify.TokenResponder = recorded => recorded.Form.ContainsKey("refresh_token")
                ? StubIdentify.OAuthError(HttpStatusCode.BadRequest, "invalid_grant", "The refresh token is not valid.")
                : factory.Identify.DefaultTokenResponse(recorded);
        }

        using var response = await SignInFlow.PostFormAsync(client, "/Account/Refresh", WithFault(Fault.AccessTokenAsRefreshToken));
        var page = await HomePageAsync(client);

        var refresh = factory.Identify.RequestsTo(StubIdentify.TokenEndpoint).Last();
        Assert.Equal("refresh_token", refresh.Form["grant_type"]);
        Assert.Equal(tokens["access_token"], refresh.Form["refresh_token"]);
        Assert.Equal(TestWebApplicationFactory.ClientSecret, refresh.Form["client_secret"]);
        await DPoPProof.ValidateAsync(refresh.Header("DPoP"), "POST", StubIdentify.TokenEndpoint);
        Assert.Contains("AccessTokenAsRefreshToken: the refresh request sends the access token as the refresh token", page);
        Assert.Contains(
            accepted
                ? "AccessTokenAsRefreshToken: Identify accepted the access token as a refresh token. The sample keeps its tokens."
                : "The token endpoint returned HTTP 400: invalid_grant",
            page);
        var after = (await TestSession.GetAsync(client)).Tokens;
        Assert.Equal(tokens["access_token"], after["access_token"]);
        Assert.Equal(tokens["refresh_token"], after["refresh_token"]);
    }

    [Fact]
    public async Task RevokeRefreshTokenSendsTheRefreshTokenWithItsHint()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(par: false));
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);

        using var response = await SignInFlow.PostFormAsync(client, "/Account/Revoke", WithFault(Fault.RevokeRefreshToken));

        var form = Single(factory, StubIdentify.RevocationEndpoint).Form;
        Assert.Equal(StubIdentify.RefreshToken, form["token"]);
        Assert.Equal("refresh_token", form["token_type_hint"]);
        Assert.Equal(TestWebApplicationFactory.ClientId, form["client_id"]);
        Assert.Equal(TestWebApplicationFactory.ClientSecret, form["client_secret"]);
        Assert.Contains("The revocation succeeded. The session keeps the revoked refresh token and its access token.", await HomePageAsync(client));
    }

    [Fact]
    public async Task RevokeRefreshTokenNeedsARefreshToken()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(par: false));
        using var client = SignInFlow.CreateHttpsClient(factory);
        factory.Identify.TokenResponder = recorded =>
        {
            using var response = factory.Identify.DefaultTokenResponse(recorded);
            var body = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(response.Content.ReadAsStringAsync().GetAwaiter().GetResult())!;
            body.Remove("refresh_token");
            return StubIdentify.Json(HttpStatusCode.OK, body);
        };
        await SignInFlow.SignInAsync(client, factory);

        using var revokeResponse = await SignInFlow.PostFormAsync(client, "/Account/Revoke", WithFault(Fault.RevokeRefreshToken));

        Assert.Contains("The fault RevokeRefreshToken needs a refresh token, and the session has none. The request was not sent.", await HomePageAsync(client));
        Assert.Empty(factory.Identify.RequestsTo(StubIdentify.RevocationEndpoint));
    }

    [Fact]
    public async Task TheNewFaultsAreShownInTheirForms()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);

        var anonymousPage = WebUtility.HtmlDecode(await client.GetStringAsync("/"));
        foreach (var fault in new[]
        {
            Fault.ParUnknownScope, Fault.ProofWithoutJwk, Fault.AssertionWithoutIss, Fault.AssertionWithoutSub, Fault.AssertionAudienceTrailingSlash,
            Fault.AssertionLongLived, Fault.WrongAssertionType, Fault.ShortCodeVerifier, Fault.LongCodeVerifier, Fault.TokenWithoutRedirectUri
        })
        {
            Assert.Contains($"<option value=\"{fault}\">{fault}: " + FaultInjection.Describe(fault), anonymousPage);
        }

        await SignInFlow.SignInAsync(client, factory);
        var page = await client.GetStringAsync("/");
        foreach (var fault in new[] { Fault.AccessTokenAsRefreshToken, Fault.RevokeRefreshToken })
        {
            Assert.Contains($"value=\"{fault}\"", page);
            Assert.NotEqual(string.Empty, FaultInjection.Describe(fault));
        }
    }

    [Fact]
    public async Task TheNewFaultsAreIgnoredWhenFaultInjectionIsOff()
    {
        var settings = Settings(par: false);
        settings["Testing:EnableFaultInjection"] = "false";
        using var factory = new TestWebApplicationFactory(settings: settings);
        using var client = SignInFlow.CreateHttpsClient(factory);
        var request = await SignInFlow.StartAsync(client, factory, WithFault(Fault.ShortCodeVerifier));
        using var callback = await SignInFlow.CompleteAsync(client, factory, request);
        await SignInFlow.AssertSignedInAsync(client, callback);
        var accessToken = (await TestSession.GetAsync(client)).Tokens["access_token"];

        // The revocation first, because a refresh replaces the access token of the session.
        using var revokeResponse = await SignInFlow.PostFormAsync(client, "/Account/Revoke", WithFault(Fault.RevokeRefreshToken));
        using var refreshResponse = await SignInFlow.PostFormAsync(client, "/Account/Refresh", WithFault(Fault.AccessTokenAsRefreshToken));

        Assert.Equal(43, factory.Identify.RequestsTo(StubIdentify.TokenEndpoint).First().Form["code_verifier"].Length);
        Assert.Equal(StubIdentify.RefreshToken, factory.Identify.RequestsTo(StubIdentify.TokenEndpoint).Last().Form["refresh_token"]);
        var revocation = Single(factory, StubIdentify.RevocationEndpoint).Form;
        Assert.Equal(accessToken, revocation["token"]);
        Assert.Equal("access_token", revocation["token_type_hint"]);
    }
}
