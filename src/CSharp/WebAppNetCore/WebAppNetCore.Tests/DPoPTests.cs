using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Net.Http.Headers;
using WebAppNetCore.OAuth;
using Xunit;

namespace WebAppNetCore.Tests;

public sealed class DPoPTests
{
    private static Dictionary<string, string?> DPoP(
        bool bindAccessTokens = true, bool sendDPoPJkt = false, bool sendProofToPar = false, string? pushedAuthorization = null)
    {
        var settings = new Dictionary<string, string?>
        {
            ["OpenIdConnectOptions:DPoP:BindAccessTokens"] = bindAccessTokens.ToString(),
            ["OpenIdConnectOptions:DPoP:SendDPoPJkt"] = sendDPoPJkt.ToString(),
            ["OpenIdConnectOptions:DPoP:SendProofToParEndpoint"] = sendProofToPar.ToString()
        };
        if (pushedAuthorization != null)
        {
            settings["OpenIdConnectOptions:PushedAuthorization"] = pushedAuthorization;
        }

        return settings;
    }

    [Fact]
    public void TheThumbprintOfTheRfc7638ExampleKeyIsCorrect()
    {
        // RFC 7638 section 3.1.
        const string n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

        Assert.Equal("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", DPoPKey.ComputeThumbprint(n, "AQAB"));
    }

    [Fact]
    public async Task AProofHasTheRequiredHeaderAndClaimsAndNoQueryInHtu()
    {
        using var key = DPoPKey.Create();

        var first = await DPoPProof.ValidateAsync(
            DPoPProofFactory.Create(key, SecurityAlgorithms.RsaSsaPssSha256, "POST", "https://provider.test/runtime/oauth2/token.idp?a=b#c"),
            "POST",
            "https://provider.test/runtime/oauth2/token.idp");
        var second = DPoPProof.Read(DPoPProofFactory.Create(key, SecurityAlgorithms.RsaSsaPssSha256, "POST", "https://provider.test/x"));

        Assert.Equal("PS256", first.Alg);
        Assert.Equal(key.Thumbprint, first.Thumbprint);
        Assert.Null(first.Claim("nonce"));
        Assert.NotEqual(first.Jti, second.Jti);
        Assert.Equal(2048, key.KeySizeInBits);
    }

    [Fact]
    public async Task AResourceProofHasAthAndAChallengedProofHasTheNonce()
    {
        using var key = DPoPKey.Create();

        var proof = await DPoPProof.ValidateAsync(
            DPoPProofFactory.Create(key, SecurityAlgorithms.RsaSha256, "GET", StubIdentify.UserInfoEndpoint, "access-token", "server-nonce"),
            "GET",
            StubIdentify.UserInfoEndpoint,
            "access-token");

        Assert.Equal("RS256", proof.Alg);
        Assert.Equal("server-nonce", proof.Claim("nonce"));
    }

    [Fact]
    public async Task BoundAccessTokensUseTheKeyOfTheSignInAtTheTokenEndpointAndAtUserInfo()
    {
        using var factory = new TestWebApplicationFactory(settings: DPoP());
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.SignInAsync(client, factory);

        Assert.False(request.Parameters.ContainsKey("dpop_jkt"));
        var tokenRequest = Assert.Single(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint));
        var tokenProof = await DPoPProof.ValidateAsync(tokenRequest.Header("DPoP"), "POST", StubIdentify.TokenEndpoint);
        Assert.Equal("PS256", tokenProof.Alg);

        var session = await TestSession.GetAsync(client);
        Assert.Equal("DPoP", session.Tokens["token_type"]);
        var accessToken = session.Tokens["access_token"];
        Assert.Equal(tokenProof.Thumbprint, new JsonWebToken(accessToken).GetPayloadValue<System.Text.Json.JsonElement>("cnf").GetProperty("jkt").GetString());

        var userInfoRequest = Assert.Single(factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint));
        Assert.Equal($"DPoP {accessToken}", userInfoRequest.Header("Authorization"));
        var userInfoProof = await DPoPProof.ValidateAsync(userInfoRequest.Header("DPoP"), "GET", StubIdentify.UserInfoEndpoint, accessToken);
        Assert.Equal(tokenProof.Thumbprint, userInfoProof.Thumbprint);
        Assert.Equal("user@provider.test", session.Claim("email"));
    }

    [Fact]
    public async Task DPoPJktInADirectRequestIsTheThumbprintOfTheTokenProofKey()
    {
        using var factory = new TestWebApplicationFactory(settings: DPoP(sendDPoPJkt: true));
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.SignInAsync(client, factory);

        var tokenProof = DPoPProof.Read(Assert.Single(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint)).Header("DPoP")!);
        Assert.Equal(tokenProof.Thumbprint, request.BrowserParameters["dpop_jkt"]);
    }

    [Fact]
    public async Task DPoPJktIsPushedAndTheBrowserGetsOnlyClientIdAndRequestUri()
    {
        using var factory = new TestWebApplicationFactory(settings: DPoP(sendDPoPJkt: true, pushedAuthorization: "Require"));
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.SignInAsync(client, factory);

        Assert.Equal(new[] { "client_id", "request_uri" }, request.BrowserParameters.Keys.OrderBy(k => k));
        var par = Assert.Single(factory.Identify.RequestsTo(StubIdentify.ParEndpoint));
        Assert.Null(par.Header("DPoP"));
        var tokenProof = DPoPProof.Read(Assert.Single(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint)).Header("DPoP")!);
        Assert.Equal(tokenProof.Thumbprint, par.Form["dpop_jkt"]);
    }

    [Fact]
    public async Task TheParProofUsesTheKeyOfTheTokenProof()
    {
        using var factory = new TestWebApplicationFactory(settings: DPoP(sendProofToPar: true, pushedAuthorization: "Require"));
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInFlow.SignInAsync(client, factory);

        var par = Assert.Single(factory.Identify.RequestsTo(StubIdentify.ParEndpoint));
        Assert.False(par.Form.ContainsKey("dpop_jkt"));
        var parProof = await DPoPProof.ValidateAsync(par.Header("DPoP"), "POST", StubIdentify.ParEndpoint);
        var tokenProof = DPoPProof.Read(Assert.Single(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint)).Header("DPoP")!);
        Assert.Equal(tokenProof.Thumbprint, parProof.Thumbprint);
        Assert.NotEqual(tokenProof.Jti, parProof.Jti);
    }

    [Fact]
    public async Task SendDPoPJktAloneBindsTheCodeButSendsNoProof()
    {
        // A combination that cannot succeed at Identify: the code is bound to the key, and the redemption has no proof.
        using var factory = new TestWebApplicationFactory(settings: DPoP(bindAccessTokens: false, sendDPoPJkt: true));
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.SignInAsync(client, factory);

        Assert.False(string.IsNullOrEmpty(request.BrowserParameters["dpop_jkt"]));
        Assert.Null(Assert.Single(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint)).Header("DPoP"));
    }

    [Fact]
    public async Task WithoutDPoPSettingsNoRequestHasAProof()
    {
        using var factory = new TestWebApplicationFactory(settings: new Dictionary<string, string?> { ["OpenIdConnectOptions:PushedAuthorization"] = "Require" });
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.SignInAsync(client, factory);

        Assert.False(request.Parameters.ContainsKey("dpop_jkt"));
        Assert.All(factory.Identify.Requests, r => Assert.Null(r.Header("DPoP")));
        Assert.StartsWith("Bearer ", Assert.Single(factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint)).Header("Authorization"));
    }

    [Fact]
    public async Task ABearerTokenResponseToAProofIsRejected()
    {
        using var factory = new TestWebApplicationFactory(settings: DPoP());
        factory.Identify.TokenResponder = recorded =>
        {
            var body = new Dictionary<string, object>
            {
                ["access_token"] = factory.Identify.IssueAccessToken(),
                ["token_type"] = "Bearer",
                ["id_token"] = factory.Identify.IssueIdToken(factory.Identify.Nonce)
            };
            return StubIdentify.Json(HttpStatusCode.OK, body);
        };
        using var client = SignInFlow.CreateHttpsClient(factory);
        var request = await SignInFlow.StartAsync(client, factory);

        using var callback = await SignInFlow.CompleteAsync(client, factory, request);

        var message = SignInFlow.ErrorMessage(await SignInFlow.AssertErrorPageAsync(client, callback));
        Assert.Equal(
            "The token endpoint returned token_type 'Bearer', but the token request had a DPoP proof. The access token is not bound to the key.",
            message);
    }

    [Fact]
    public async Task TheTokenRequestIsRetriedOnceWithTheServerNonceAndANewAssertion()
    {
        using var certificate = new TestCertificateFile();
        var settings = DPoP();
        foreach (var setting in certificate.PrivateKeyJwtSettings())
        {
            settings[setting.Key] = setting.Value;
        }

        using var factory = new TestWebApplicationFactory(settings: settings);
        var challenged = false;
        factory.Identify.TokenResponder = recorded =>
        {
            if (!challenged)
            {
                challenged = true;
                var challenge = StubIdentify.OAuthError(HttpStatusCode.BadRequest, "use_dpop_nonce", "Authorization server requires nonce in DPoP proof");
                challenge.Headers.Add("DPoP-Nonce", "token-nonce");
                return challenge;
            }

            return factory.Identify.DefaultTokenResponse(recorded);
        };
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInFlow.SignInAsync(client, factory);

        var requests = factory.Identify.RequestsTo(StubIdentify.TokenEndpoint);
        Assert.Equal(2, requests.Count);
        var firstProof = await DPoPProof.ValidateAsync(requests[0].Header("DPoP"), "POST", StubIdentify.TokenEndpoint);
        var retryProof = await DPoPProof.ValidateAsync(requests[1].Header("DPoP"), "POST", StubIdentify.TokenEndpoint);
        Assert.Null(firstProof.Claim("nonce"));
        Assert.Equal("token-nonce", retryProof.Claim("nonce"));
        Assert.NotEqual(firstProof.Jti, retryProof.Jti);
        Assert.Equal(firstProof.Thumbprint, retryProof.Thumbprint);
        Assert.NotEqual(
            new JsonWebToken(requests[0].Form["client_assertion"]).Id,
            new JsonWebToken(requests[1].Form["client_assertion"]).Id);
    }

    [Fact]
    public async Task TheUserInfoRequestIsRetriedOnceWithTheResourceServerNonce()
    {
        using var factory = new TestWebApplicationFactory(settings: DPoP());
        var challenged = false;
        factory.Identify.UserInfoResponder = recorded =>
        {
            if (!challenged)
            {
                challenged = true;
                var challenge = new HttpResponseMessage(HttpStatusCode.Unauthorized);
                challenge.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue("DPoP", "error=\"use_dpop_nonce\", error_description=\"Resource server requires nonce in DPoP proof\""));
                challenge.Headers.Add("DPoP-Nonce", "resource-nonce");
                return challenge;
            }

            return factory.Identify.DefaultUserInfoResponse(recorded);
        };
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInFlow.SignInAsync(client, factory);

        var requests = factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint);
        Assert.Equal(2, requests.Count);
        var accessToken = (await TestSession.GetAsync(client)).Tokens["access_token"];
        var retryProof = await DPoPProof.ValidateAsync(requests[1].Header("DPoP"), "GET", StubIdentify.UserInfoEndpoint, accessToken);
        Assert.Equal("resource-nonce", retryProof.Claim("nonce"));
    }

    [Fact]
    public async Task ASecondNonceChallengeFailsTheRequest()
    {
        using var factory = new TestWebApplicationFactory(settings: DPoP());
        factory.Identify.TokenResponder = _ =>
        {
            var challenge = StubIdentify.OAuthError(HttpStatusCode.BadRequest, "use_dpop_nonce", "Authorization server requires nonce in DPoP proof");
            challenge.Headers.Add("DPoP-Nonce", "another-nonce");
            return challenge;
        };
        using var client = SignInFlow.CreateHttpsClient(factory);
        var request = await SignInFlow.StartAsync(client, factory);

        using var callback = await SignInFlow.CompleteAsync(client, factory, request);

        var message = SignInFlow.ErrorMessage(await SignInFlow.AssertErrorPageAsync(client, callback));
        Assert.StartsWith("The token endpoint returned HTTP 400: use_dpop_nonce", message);
        Assert.Equal(2, factory.Identify.RequestsTo(StubIdentify.TokenEndpoint).Count);
    }

    [Theory]
    [InlineData("OpenIdConnectOptions:DPoP:BindAccessTokens", "yes")]
    [InlineData("OpenIdConnectOptions:DPoP:SigningAlgorithm", "ES256")]
    public void AnInvalidValueStopsTheApplication(string key, string value)
    {
        using var factory = new TestWebApplicationFactory(settings: new Dictionary<string, string?> { [key] = value });

        var exception = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
        Assert.Contains($"'{key}' has the invalid value '{value}'", exception.ToString());
    }
}
