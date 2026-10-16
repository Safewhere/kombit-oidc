using Microsoft.IdentityModel.Tokens;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WebAppNetCore.OAuth;
using Xunit;

namespace WebAppNetCore.Tests;

/// <summary>
/// The faults of the pushed request, the DPoP proofs, the client assertions, and the token requests, and the introspection,
/// revocation, public client, and client credentials actions. Each test checks the outgoing request at the stub Identify.
/// </summary>
public sealed class MoreFaultTests
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

    private static async Task<AuthorizationRequest> SignInWithFaultAsync(HttpClient client, TestWebApplicationFactory factory, Fault fault)
    {
        var request = await SignInFlow.StartAsync(client, factory, WithFault(fault));
        using var callback = await SignInFlow.CompleteAsync(client, factory, request);
        await SignInFlow.AssertSignedInAsync(client, callback);
        return request;
    }

    private static RecordedRequest Single(TestWebApplicationFactory factory, string endpoint) => Assert.Single(factory.Identify.RequestsTo(endpoint));

    private static JsonElement Part(string jwt, int index) =>
        JsonDocument.Parse(Base64UrlEncoder.Decode(jwt.Split('.')[index])).RootElement.Clone();

    [Theory]
    [InlineData(Fault.ParMissingCodeChallenge)]
    [InlineData(Fault.ParMissingCodeChallengeMethod)]
    [InlineData(Fault.ParPlainPkce)]
    [InlineData(Fault.ParMissingRedirectUri)]
    [InlineData(Fault.ParRepeatedParameter)]
    [InlineData(Fault.ParRequestParameter)]
    [InlineData(Fault.ParNestedRequestUri)]
    [InlineData(Fault.UnknownResponseTypeComponent)]
    [InlineData(Fault.ResponseTypeWithToken)]
    public async Task PushedRequestFaultsChangeOnlyTheirParameter(Fault fault)
    {
        using var factory = new TestWebApplicationFactory(settings: Settings());
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInFlow.StartAsync(client, factory, WithFault(fault));

        var form = Single(factory, StubIdentify.ParEndpoint).Form;
        Assert.Equal(TestWebApplicationFactory.ClientId, form["client_id"]);
        Assert.Equal(fault == Fault.ParMissingRedirectUri, !form.ContainsKey("redirect_uri"));
        Assert.Equal(fault == Fault.ParMissingCodeChallenge, !form.ContainsKey("code_challenge"));
        Assert.Equal(fault == Fault.ParMissingCodeChallengeMethod, !form.ContainsKey("code_challenge_method"));
        switch (fault)
        {
            case Fault.ParPlainPkce:
                Assert.Equal("plain", form["code_challenge_method"]);
                break;
            case Fault.ParRepeatedParameter:
                Assert.Equal("openid,openid", form["scope"]);
                break;
            case Fault.ParRequestParameter:
                Assert.Equal("none", Part(form["request"], 0).GetProperty("alg").GetString());
                Assert.Equal(TestWebApplicationFactory.ClientId, Part(form["request"], 1).GetProperty("client_id").GetString());
                break;
            case Fault.ParNestedRequestUri:
                Assert.StartsWith("urn:ietf:params:oauth:request_uri:", form["request_uri"]);
                break;
            case Fault.UnknownResponseTypeComponent:
                Assert.Equal("code unknown", form["response_type"]);
                break;
            case Fault.ResponseTypeWithToken:
                Assert.Equal("code token", form["response_type"]);
                break;
            default:
                Assert.Equal("code", form["response_type"]);
                break;
        }
    }

    [Fact]
    public async Task ParProofTokenEndpointHtuGivesThePushedRequestAProofForTheTokenEndpoint()
    {
        var settings = Settings(dpop: true);
        settings["OpenIdConnectOptions:DPoP:SendDPoPJkt"] = "false";
        settings["OpenIdConnectOptions:DPoP:SendProofToParEndpoint"] = "true";
        using var factory = new TestWebApplicationFactory(settings: settings);
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInFlow.StartAsync(client, factory, WithFault(Fault.ParProofTokenEndpointHtu));

        await DPoPProof.ValidateAsync(Single(factory, StubIdentify.ParEndpoint).Header("DPoP"), "POST", StubIdentify.TokenEndpoint);
    }

    [Theory]
    [InlineData(Fault.ProofWrongHtm)]
    [InlineData(Fault.ProofHtuPathCase)]
    [InlineData(Fault.ProofIatFuture)]
    [InlineData(Fault.ProofIatOld)]
    [InlineData(Fault.ProofIatRecent)]
    [InlineData(Fault.ProofNbfFuture)]
    [InlineData(Fault.ProofTypJwt)]
    [InlineData(Fault.ProofPrivateJwkMembers)]
    [InlineData(Fault.ProofHtuWithQuery)]
    [InlineData(Fault.ProofHtuHostUpperCase)]
    public async Task TokenProofFaultsChangeOnlyTheirClaimOrHeader(Fault fault)
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true, par: false));
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInWithFaultAsync(client, factory, fault);

        var proof = Single(factory, StubIdentify.TokenEndpoint).Header("DPoP")!;
        var header = Part(proof, 0);
        var payload = Part(proof, 1);
        Assert.Equal(request.Parameters["dpop_jkt"], DPoPProof.Read(proof).Thumbprint);
        var now = DateTimeOffset.UtcNow;
        var iat = DateTimeOffset.FromUnixTimeSeconds(payload.GetProperty("iat").GetInt64());
        Assert.Equal(fault == Fault.ProofWrongHtm ? "GET" : "POST", payload.GetProperty("htm").GetString());
        Assert.Equal(fault == Fault.ProofTypJwt ? "JWT" : "dpop+jwt", header.GetProperty("typ").GetString());
        Assert.Equal(fault == Fault.ProofPrivateJwkMembers, header.GetProperty("jwk").TryGetProperty("d", out _));
        Assert.Equal(fault == Fault.ProofNbfFuture, payload.TryGetProperty("nbf", out _));
        var htu = payload.GetProperty("htu").GetString();
        var expectedHtu = fault switch
        {
            Fault.ProofHtuPathCase => "https://provider.test/RUNTIME/OAUTH2/TOKEN.IDP",
            Fault.ProofHtuWithQuery => StubIdentify.TokenEndpoint + "?x=1",
            Fault.ProofHtuHostUpperCase => "https://PROVIDER.TEST/runtime/oauth2/token.idp",
            _ => StubIdentify.TokenEndpoint
        };
        Assert.Equal(expectedHtu, htu);
        var (low, high) = fault switch
        {
            Fault.ProofIatFuture => (110, 130),
            Fault.ProofIatOld => (-100, -80),
            Fault.ProofIatRecent => (-40, -20),
            _ => (-10, 10)
        };
        Assert.InRange(iat, now.AddSeconds(low), now.AddSeconds(high));
        if (fault == Fault.ProofNbfFuture)
        {
            Assert.InRange(DateTimeOffset.FromUnixTimeSeconds(payload.GetProperty("nbf").GetInt64()), now.AddSeconds(110), now.AddSeconds(130));
        }
    }

    [Fact]
    public async Task TwoProofsSendsTwoDPoPHeaderValues()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true, par: false));
        factory.Identify.TokenResponder = recorded => StubIdentify.OAuthError(HttpStatusCode.BadRequest, "invalid_dpop_proof", "Two proofs.");
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.StartAsync(client, factory, WithFault(Fault.TwoProofs));
        using var callback = await SignInFlow.CompleteAsync(client, factory, request);

        var proofs = Single(factory, StubIdentify.TokenEndpoint).Header("DPoP")!.Split(',').Select(p => p.Trim()).ToArray();
        Assert.Equal(2, proofs.Length);
        Assert.NotEqual(proofs[0], proofs[1]);
        Assert.All(proofs, p => Assert.Equal(request.Parameters["dpop_jkt"], DPoPProof.Read(p).Thumbprint));
    }

    [Fact]
    public async Task WrongDPoPKeyThenRetrySendsTheCodeWithANewKeyAndThenWithTheKeyOfTheSignIn()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true, par: false));
        string? boundKey = null;
        factory.Identify.TokenResponder = recorded => DPoPProof.Read(recorded.Header("DPoP")!).Thumbprint == boundKey
            ? factory.Identify.DefaultTokenResponse(recorded)
            : StubIdentify.OAuthError(HttpStatusCode.BadRequest, "invalid_grant", "The DPoP proof key is not the key that the authorization code is bound to.");
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.StartAsync(client, factory, WithFault(Fault.WrongDPoPKeyThenRetry));
        boundKey = request.Parameters["dpop_jkt"];
        using var callback = await SignInFlow.CompleteAsync(client, factory, request);
        await SignInFlow.AssertSignedInAsync(client, callback);

        var tokenRequests = factory.Identify.RequestsTo(StubIdentify.TokenEndpoint);
        Assert.Equal(2, tokenRequests.Count);
        Assert.NotEqual(boundKey, DPoPProof.Read(tokenRequests[0].Header("DPoP")!).Thumbprint);
        Assert.Equal(boundKey, DPoPProof.Read(tokenRequests[1].Header("DPoP")!).Thumbprint);
        Assert.All(tokenRequests, r => Assert.Equal(SignInFlow.Code, r.Form["code"]));
        Assert.Contains("WrongDPoPKeyThenRetry: the request with a new key failed", WebUtility.HtmlDecode(await client.GetStringAsync("/")));
    }

    [Theory]
    [InlineData(Fault.AssertionWithoutJti)]
    [InlineData(Fault.AssertionAndClientSecret)]
    [InlineData(Fault.ClientIdNotSubject)]
    public async Task AssertionFaultsChangeThePushedAndTheTokenRequest(Fault fault)
    {
        using var certificate = new TestCertificateFile();
        using var factory = new TestWebApplicationFactory(settings: PrivateKeyJwtSettings(certificate));
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInWithFaultAsync(client, factory, fault);

        foreach (var endpoint in new[] { StubIdentify.ParEndpoint, StubIdentify.TokenEndpoint })
        {
            var form = Single(factory, endpoint).Form;
            var payload = Part(form["client_assertion"], 1);
            Assert.Equal(TestWebApplicationFactory.ClientId, payload.GetProperty("sub").GetString());
            Assert.Equal(fault != Fault.AssertionWithoutJti, payload.TryGetProperty("jti", out _));
            Assert.Equal(fault == Fault.AssertionAndClientSecret, form.ContainsKey("client_secret"));
            Assert.Equal(fault == Fault.ClientIdNotSubject ? OtherClientId : TestWebApplicationFactory.ClientId, form["client_id"]);
        }
    }

    [Fact]
    public async Task WrongCodeVerifierSendsAVerifierThatDoesNotMatchTheChallenge()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings());
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInWithFaultAsync(client, factory, Fault.WrongCodeVerifier);

        var verifier = Single(factory, StubIdentify.TokenEndpoint).Form["code_verifier"];
        Assert.Equal(43, verifier.Length);
        Assert.NotEqual(request.Parameters["code_challenge"], Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))));
    }

    [Fact]
    public async Task RedeemCodeAfter5SecondsWaitsBeforeTheTokenRequest()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings());
        using var client = SignInFlow.CreateHttpsClient(factory);
        var request = await SignInFlow.StartAsync(client, factory, WithFault(Fault.RedeemCodeAfter5Seconds));

        var watch = Stopwatch.StartNew();
        using var callback = await SignInFlow.CompleteAsync(client, factory, request);
        watch.Stop();

        await SignInFlow.AssertSignedInAsync(client, callback);
        Assert.True(watch.Elapsed >= TimeSpan.FromSeconds(4.5), "The callback took " + watch.Elapsed);
        Assert.Contains("RedeemCodeAfter5Seconds: the sample waits 5 seconds", WebUtility.HtmlDecode(await client.GetStringAsync("/")));
    }

    [Fact]
    public async Task NoDPoPProofOnRefreshOmitsTheRefreshProof()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true, par: false));
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);

        using var response = await SignInFlow.PostFormAsync(client, "/Account/Refresh", WithFault(Fault.NoDPoPProof));

        var refresh = factory.Identify.RequestsTo(StubIdentify.TokenEndpoint).Last();
        Assert.Equal("refresh_token", refresh.Form["grant_type"]);
        Assert.Null(refresh.Header("DPoP"));
    }

    [Fact]
    public async Task ReplayClientAssertionSendsTheSameAssertionInTwoRefreshRequests()
    {
        using var certificate = new TestCertificateFile();
        using var factory = new TestWebApplicationFactory(settings: PrivateKeyJwtSettings(certificate, dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);
        factory.Identify.TokenResponder = recorded => factory.Identify.RequestsTo(StubIdentify.TokenEndpoint).Count > 2
            ? StubIdentify.OAuthError(HttpStatusCode.BadRequest, "invalid_client", "The client assertion was used before.")
            : factory.Identify.DefaultTokenResponse(recorded);

        using var response = await SignInFlow.PostFormAsync(client, "/Account/Refresh", WithFault(Fault.ReplayClientAssertion));
        var page = WebUtility.HtmlDecode(await client.GetStringAsync("/"));

        var requests = factory.Identify.RequestsTo(StubIdentify.TokenEndpoint);
        Assert.Equal(3, requests.Count);
        Assert.Equal(requests[1].Form["client_assertion"], requests[2].Form["client_assertion"]);
        Assert.NotEqual(requests[1].Header("DPoP"), requests[2].Header("DPoP"));
        Assert.Contains("The token endpoint returned HTTP 400: invalid_client", page);
    }

    [Fact]
    public async Task IntrospectionSendsTheAccessTokenWithTheConfiguredClientAuthentication()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true, par: false));
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);
        var accessToken = (await TestSession.GetAsync(client)).Tokens["access_token"];

        using var response = await SignInFlow.PostFormAsync(client, "/Account/Introspect");
        var page = WebUtility.HtmlDecode(await client.GetStringAsync("/"));

        var form = Single(factory, StubIdentify.IntrospectionEndpoint).Form;
        Assert.Equal(accessToken, form["token"]);
        Assert.Equal("access_token", form["token_type_hint"]);
        Assert.Equal(TestWebApplicationFactory.ClientSecret, form["client_secret"]);
        Assert.Contains("The introspection succeeded:", page);
        Assert.Contains("\"active\": true", page);
    }

    [Fact]
    public async Task IntrospectWithClientSecretUsesTheSecretInsteadOfTheAssertion()
    {
        using var certificate = new TestCertificateFile();
        using var factory = new TestWebApplicationFactory(settings: PrivateKeyJwtSettings(certificate, dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);

        using var response = await SignInFlow.PostFormAsync(client, "/Account/Introspect", WithFault(Fault.IntrospectWithClientSecret));

        var form = Single(factory, StubIdentify.IntrospectionEndpoint).Form;
        Assert.Equal(TestWebApplicationFactory.ClientSecret, form["client_secret"]);
        Assert.False(form.ContainsKey("client_assertion"));
    }

    [Fact]
    public async Task RevocationSendsTheAccessToken()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(par: false));
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);
        var accessToken = (await TestSession.GetAsync(client)).Tokens["access_token"];

        using var response = await SignInFlow.PostFormAsync(client, "/Account/Revoke");

        var form = Single(factory, StubIdentify.RevocationEndpoint).Form;
        Assert.Equal(accessToken, form["token"]);
        Assert.Equal("access_token", form["token_type_hint"]);
        Assert.Contains("The revocation succeeded.", WebUtility.HtmlDecode(await client.GetStringAsync("/")));
    }

    [Fact]
    public async Task APublicClientSendsOnlyItsClientId()
    {
        var settings = Settings(dpop: true);
        settings["OpenIdConnectOptions:TokenAuthnMethod"] = "none";
        using var factory = new TestWebApplicationFactory(settings: settings);
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInFlow.SignInAsync(client, factory);

        foreach (var endpoint in new[] { StubIdentify.ParEndpoint, StubIdentify.TokenEndpoint })
        {
            var recorded = Single(factory, endpoint);
            Assert.Equal(TestWebApplicationFactory.ClientId, recorded.Form["client_id"]);
            Assert.False(recorded.Form.ContainsKey("client_secret"));
            Assert.False(recorded.Form.ContainsKey("client_assertion"));
            Assert.Null(recorded.Header("Authorization"));
        }
    }

    [Fact]
    public async Task ClientCredentialsGetsADPoPBoundTokenWithoutASignIn()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true, par: false));
        using var client = SignInFlow.CreateHttpsClient(factory);

        using var response = await SignInFlow.PostFormAsync(client, "/Account/ClientCredentials");
        var page = WebUtility.HtmlDecode(await client.GetStringAsync("/"));

        var token = Single(factory, StubIdentify.TokenEndpoint);
        Assert.Equal("client_credentials", token.Form["grant_type"]);
        await DPoPProof.ValidateAsync(token.Header("DPoP"), "POST", StubIdentify.TokenEndpoint);
        Assert.Contains("The client credentials request succeeded: token_type DPoP", page);
        Assert.Contains("Bound to the key: Yes.", page);
        Assert.Empty(factory.Identify.RequestsTo(StubIdentify.ParEndpoint));
    }
}
