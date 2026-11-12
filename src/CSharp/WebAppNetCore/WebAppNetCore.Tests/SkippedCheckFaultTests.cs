using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using WebAppNetCore.OAuth;
using Xunit;

namespace WebAppNetCore.Tests;

/// <summary>
/// The faults for checks that a server can skip without notice: token proofs without a required claim, forged and old UserInfo
/// proofs, the access token in the query, the client assertion of the pushed request at the token endpoint, a client
/// assertion with nbf in the future, and requests without client authentication. Each test checks the outgoing request at the
/// stub Identify.
/// </summary>
public sealed class SkippedCheckFaultTests
{
    private static Dictionary<string, string?> Settings(bool dpop = false, bool par = true)
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

    private static Dictionary<string, string?> PrivateKeyJwtSettings(TestCertificateFile certificate, bool dpop = false, bool par = true)
    {
        var settings = Settings(dpop, par);
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
            ValidateLifetime = false,
            RequireExpirationTime = false,
            ValidTypes = new[] { "JWT", "dpop+jwt" }
        });
        return result.IsValid;
    }

    /// <summary>A UserInfo rejection as RFC 9449 section 7.1 describes it: HTTP 401 with a DPoP challenge and no body.</summary>
    private static HttpResponseMessage DPoPChallenge(string error)
    {
        var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
        response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue("DPoP", $"error=\"{error}\", algs=\"PS256\""));
        return response;
    }

    [Theory]
    [InlineData(Fault.ProofWithoutHtm, "htm")]
    [InlineData(Fault.ProofWithoutHtu, "htu")]
    [InlineData(Fault.ProofWithoutIat, "iat")]
    public async Task ProofWithoutAClaimOmitsOnlyThatClaimOfTheTokenProof(Fault fault, string claim)
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true, par: false));
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInWithFaultAsync(client, factory, fault);

        var proof = Single(factory, StubIdentify.TokenEndpoint).Header("DPoP")!;
        var read = DPoPProof.Read(proof);
        Assert.Equal(request.Parameters["dpop_jkt"], read.Thumbprint);
        Assert.Equal("dpop+jwt", read.Header.GetProperty("typ").GetString());
        Assert.True(await VerifiesWithAsync(proof, new JsonWebKey(read.Header.GetProperty("jwk").GetRawText())));
        Assert.Equal(
            new[] { "htm", "htu", "iat", "jti" }.Where(name => name != claim),
            read.Payload.EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal));
        Assert.Equal(fault == Fault.ProofWithoutHtm ? null : "POST", read.Claim("htm"));
        Assert.Equal(fault == Fault.ProofWithoutHtu ? null : StubIdentify.TokenEndpoint, read.Claim("htu"));

        // The UserInfo call of the sign-in has a correct proof.
        var accessToken = (await TestSession.GetAsync(client)).Tokens["access_token"];
        await DPoPProof.ValidateAsync(Single(factory, StubIdentify.UserInfoEndpoint).Header("DPoP"), "GET", StubIdentify.UserInfoEndpoint, accessToken);
    }

    [Fact]
    public async Task ReplayParAssertionAtTokenSendsTheAssertionOfThePushedRequestAgain()
    {
        using var certificate = new TestCertificateFile();
        using var factory = new TestWebApplicationFactory(settings: PrivateKeyJwtSettings(certificate, dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInWithFaultAsync(client, factory, Fault.ReplayParAssertionAtToken);

        var pushedAssertion = Single(factory, StubIdentify.ParEndpoint).Form["client_assertion"];
        var token = Single(factory, StubIdentify.TokenEndpoint);
        Assert.Equal(pushedAssertion, token.Form["client_assertion"]);
        Assert.Equal(ClientAuthentication.ClientAssertionType, token.Form["client_assertion_type"]);
        Assert.Equal(TestWebApplicationFactory.ClientId, token.Form["client_id"]);
        var assertion = await CodeFlowTests.ValidateClientAssertionAsync(token.Form["client_assertion"], certificate);
        Assert.Equal(StubIdentify.Issuer, assertion.GetPayloadValue<string>("aud"));
        // Only the assertion is the old one: the token request has the code, the verifier, and a new proof.
        Assert.Equal(SignInFlow.Code, token.Form["code"]);
        Assert.True(token.Form.ContainsKey("code_verifier"));
        await DPoPProof.ValidateAsync(token.Header("DPoP"), "POST", StubIdentify.TokenEndpoint);

        // The refresh request has a new assertion.
        using var refresh = await SignInFlow.PostFormAsync(client, "/Account/Refresh");
        Assert.NotEqual(pushedAssertion, factory.Identify.RequestsTo(StubIdentify.TokenEndpoint).Last().Form["client_assertion"]);
    }

    [Theory]
    [InlineData("client_secret_post", true)]
    [InlineData("private_key_jwt", false)]
    public async Task ReplayParAssertionAtTokenStopsTheSignInWithoutAnAssertionOfAPushedRequest(string method, bool par)
    {
        using var certificate = new TestCertificateFile();
        var settings = PrivateKeyJwtSettings(certificate, par: par);
        settings["OpenIdConnectOptions:TokenAuthnMethod"] = method;
        using var factory = new TestWebApplicationFactory(settings: settings);
        using var client = SignInFlow.CreateHttpsClient(factory);

        using var response = await SignInFlow.PostSignInAsync(client, WithFault(Fault.ReplayParAssertionAtToken));

        Assert.Equal(
            "The fault ReplayParAssertionAtToken needs TokenAuthnMethod private_key_jwt and a pushed authorization request. The sign-in did not start.",
            SignInFlow.ErrorMessage(await SignInFlow.AssertErrorPageAsync(client, response)));
        Assert.Empty(factory.Identify.Requests);
    }

    [Fact]
    public async Task AssertionNbfFutureSetsNbfInTheAssertionsAtParAndAtTheTokenEndpoint()
    {
        using var certificate = new TestCertificateFile();
        using var factory = new TestWebApplicationFactory(settings: PrivateKeyJwtSettings(certificate));
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInWithFaultAsync(client, factory, Fault.AssertionNbfFuture);

        var clientKey = new X509SecurityKey(certificate.PublicCertificate);
        foreach (var endpoint in new[] { StubIdentify.ParEndpoint, StubIdentify.TokenEndpoint })
        {
            var assertion = Single(factory, endpoint).Form["client_assertion"];
            var payload = Part(assertion, 1);
            var now = DateTimeOffset.UtcNow;
            Assert.InRange(DateTimeOffset.FromUnixTimeSeconds(payload.GetProperty("nbf").GetInt64()), now.AddSeconds(110), now.AddSeconds(130));
            Assert.InRange(DateTimeOffset.FromUnixTimeSeconds(payload.GetProperty("iat").GetInt64()), now.AddSeconds(-10), now.AddSeconds(10));
            Assert.InRange(DateTimeOffset.FromUnixTimeSeconds(payload.GetProperty("exp").GetInt64()), now.AddSeconds(290), now.AddSeconds(310));
            Assert.Equal(TestWebApplicationFactory.ClientId, payload.GetProperty("iss").GetString());
            Assert.Equal(StubIdentify.Issuer, payload.GetProperty("aud").GetString());
            Assert.False(string.IsNullOrEmpty(payload.GetProperty("jti").GetString()));
            Assert.True(await VerifiesWithAsync(assertion, clientKey));
        }
    }

    [Theory]
    [InlineData(Fault.UserInfoProofAlgNone)]
    [InlineData(Fault.UserInfoProofSignatureOtherKey)]
    [InlineData(Fault.UserInfoProofWithoutJti)]
    [InlineData(Fault.UserInfoProofIatOld)]
    public async Task UserInfoProofFaultsForgeOnlyTheUserInfoProof(Fault fault)
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true, par: false));
        using var client = SignInFlow.CreateHttpsClient(factory);
        var request = await SignInFlow.SignInAsync(client, factory);
        var accessToken = (await TestSession.GetAsync(client)).Tokens["access_token"];
        factory.Identify.UserInfoResponder = _ => DPoPChallenge("invalid_dpop_proof");

        using var response = await SignInFlow.PostFormAsync(client, "/Account/UserInfo", WithFault(fault));

        var userInfo = factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint).Last();
        Assert.Equal(HttpMethod.Get, userInfo.Method);
        Assert.Equal("DPoP " + accessToken, userInfo.Header("Authorization"));
        var proof = userInfo.Header("DPoP")!;
        var read = DPoPProof.Read(proof);
        var jwk = new JsonWebKey(read.Header.GetProperty("jwk").GetRawText());
        Assert.Equal(request.Parameters["dpop_jkt"], read.Thumbprint);
        Assert.Equal("dpop+jwt", read.Header.GetProperty("typ").GetString());
        Assert.Equal("GET", read.Claim("htm"));
        Assert.Equal(StubIdentify.UserInfoEndpoint, read.Claim("htu"));
        Assert.Equal(DPoPProof.AccessTokenHash(accessToken), read.Claim("ath"));
        Assert.Equal(fault != Fault.UserInfoProofWithoutJti, read.Payload.TryGetProperty("jti", out _));
        var now = DateTimeOffset.UtcNow;
        var (low, high) = fault == Fault.UserInfoProofIatOld ? (-100, -80) : (-10, 10);
        Assert.InRange(DateTimeOffset.FromUnixTimeSeconds(read.Payload.GetProperty("iat").GetInt64()), now.AddSeconds(low), now.AddSeconds(high));
        switch (fault)
        {
            case Fault.UserInfoProofAlgNone:
                Assert.Equal("none", read.Alg);
                Assert.Equal(string.Empty, proof.Split('.')[2]);
                break;
            case Fault.UserInfoProofSignatureOtherKey:
                Assert.Matches("^(RS|PS)(256|384|512)$", read.Alg);
                Assert.False(await VerifiesWithAsync(proof, jwk), "The proof verifies with its jwk.");
                break;
            default:
                Assert.True(await VerifiesWithAsync(proof, jwk));
                break;
        }

        Assert.Contains("The UserInfo endpoint returned HTTP 401: invalid_dpop_proof", await HomePageAsync(client));

        // The sign-in had correct proofs.
        var signInUserInfo = factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint)[0];
        await DPoPProof.ValidateAsync(signInUserInfo.Header("DPoP"), "GET", StubIdentify.UserInfoEndpoint, accessToken);
        await DPoPProof.ValidateAsync(Single(factory, StubIdentify.TokenEndpoint).Header("DPoP"), "POST", StubIdentify.TokenEndpoint);
    }

    [Fact]
    public async Task AccessTokenInQuerySendsTheTokenInTheQueryOfAGetWithAProof()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);
        var request = await SignInFlow.SignInAsync(client, factory);
        var accessToken = (await TestSession.GetAsync(client)).Tokens["access_token"];
        factory.Identify.UserInfoResponder = _ => DPoPChallenge("invalid_token");

        using var response = await SignInFlow.PostFormAsync(client, "/Account/UserInfo", WithFault(Fault.AccessTokenInQuery));
        var page = await HomePageAsync(client);

        var userInfo = factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint).Last();
        Assert.Equal(HttpMethod.Get, userInfo.Method);
        Assert.Equal("?access_token=" + accessToken, userInfo.Query);
        Assert.Null(userInfo.Header("Authorization"));
        Assert.Empty(userInfo.Form);
        // The proof has the endpoint without the query as htu (RFC 9449 section 4.2).
        var proof = await DPoPProof.ValidateAsync(userInfo.Header("DPoP"), "GET", StubIdentify.UserInfoEndpoint, accessToken);
        Assert.Equal(request.Parameters["dpop_jkt"], proof.Thumbprint);
        Assert.Contains("The UserInfo endpoint returned HTTP 401: invalid_token", page);
        // The trace shows that the query has the token, not the token. The access token panel shows the token on purpose.
        Assert.Contains("GET " + StubIdentify.UserInfoEndpoint + "?access_token=(present)", page);
        Assert.DoesNotContain("access_token=" + accessToken, page);
    }

    [Theory]
    [InlineData(Fault.AccessTokenInQuery)]
    [InlineData(Fault.UserInfoProofAlgNone)]
    [InlineData(Fault.UserInfoProofSignatureOtherKey)]
    [InlineData(Fault.UserInfoProofWithoutJti)]
    [InlineData(Fault.UserInfoProofIatOld)]
    public async Task TheNewUserInfoFaultsNeedADPoPBoundToken(Fault fault)
    {
        using var factory = new TestWebApplicationFactory(settings: Settings());
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);

        using var response = await SignInFlow.PostFormAsync(client, "/Account/UserInfo", WithFault(fault));

        Assert.Contains($"The fault {fault} needs a DPoP-bound access token", await HomePageAsync(client));
        // Only the UserInfo request of the sign-in.
        Single(factory, StubIdentify.UserInfoEndpoint);
    }

    [Theory]
    [InlineData("/Account/Introspect", Fault.IntrospectWithoutClientAuthentication, StubIdentify.IntrospectionEndpoint, "client_secret_basic")]
    [InlineData("/Account/Introspect", Fault.IntrospectWithoutClientAuthentication, StubIdentify.IntrospectionEndpoint, "private_key_jwt")]
    [InlineData("/Account/Revoke", Fault.RevokeWithoutClientAuthentication, StubIdentify.RevocationEndpoint, "client_secret_basic")]
    [InlineData("/Account/Revoke", Fault.RevokeWithoutClientAuthentication, StubIdentify.RevocationEndpoint, "private_key_jwt")]
    public async Task TokenManagementWithoutClientAuthenticationSendsOnlyTheClientIdAndTheToken(string path, Fault fault, string endpoint, string method)
    {
        using var certificate = new TestCertificateFile();
        var settings = PrivateKeyJwtSettings(certificate, dpop: true);
        settings["OpenIdConnectOptions:TokenAuthnMethod"] = method;
        using var factory = new TestWebApplicationFactory(settings: settings);
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);
        var accessToken = (await TestSession.GetAsync(client)).Tokens["access_token"];
        var invalidClient = (Func<RecordedRequest, HttpResponseMessage>)(_ => StubIdentify.OAuthError(HttpStatusCode.Unauthorized, "invalid_client", "Client authentication failed."));
        factory.Identify.IntrospectionResponder = invalidClient;
        factory.Identify.RevocationResponder = invalidClient;

        using var response = await SignInFlow.PostFormAsync(client, path, WithFault(fault));

        var recorded = Single(factory, endpoint);
        Assert.Equal(new[] { "client_id", "token", "token_type_hint" }, recorded.Form.Keys.OrderBy(k => k, StringComparer.Ordinal));
        Assert.Equal(TestWebApplicationFactory.ClientId, recorded.Form["client_id"]);
        Assert.Equal(accessToken, recorded.Form["token"]);
        Assert.Null(recorded.Header("Authorization"));
        var endpointName = path == "/Account/Introspect" ? "introspection" : "revocation";
        Assert.Contains($"The {endpointName} endpoint returned HTTP 401: invalid_client", await HomePageAsync(client));
    }

    [Theory]
    [InlineData("client_secret_post")]
    [InlineData("client_secret_basic")]
    [InlineData("private_key_jwt")]
    public async Task RefreshWithoutClientAuthenticationSendsOnlyTheClientIdTheRefreshTokenAndTheProof(string method)
    {
        using var certificate = new TestCertificateFile();
        var settings = PrivateKeyJwtSettings(certificate, dpop: true);
        settings["OpenIdConnectOptions:TokenAuthnMethod"] = method;
        using var factory = new TestWebApplicationFactory(settings: settings);
        using var client = SignInFlow.CreateHttpsClient(factory);
        var request = await SignInFlow.SignInAsync(client, factory);
        factory.Identify.TokenResponder = recorded => recorded.Form.ContainsKey("refresh_token")
            ? StubIdentify.OAuthError(HttpStatusCode.Unauthorized, "invalid_client", "Client authentication failed.")
            : factory.Identify.DefaultTokenResponse(recorded);

        using var response = await SignInFlow.PostFormAsync(client, "/Account/Refresh", WithFault(Fault.RefreshWithoutClientAuthentication));

        var refresh = factory.Identify.RequestsTo(StubIdentify.TokenEndpoint).Last();
        Assert.Equal(new[] { "client_id", "grant_type", "refresh_token" }, refresh.Form.Keys.OrderBy(k => k, StringComparer.Ordinal));
        Assert.Equal("refresh_token", refresh.Form["grant_type"]);
        Assert.Equal(StubIdentify.RefreshToken, refresh.Form["refresh_token"]);
        Assert.Equal(TestWebApplicationFactory.ClientId, refresh.Form["client_id"]);
        Assert.Null(refresh.Header("Authorization"));
        // The proof of the key of the sign-in: only the client authentication is missing.
        var proof = await DPoPProof.ValidateAsync(refresh.Header("DPoP"), "POST", StubIdentify.TokenEndpoint);
        Assert.Equal(request.Parameters["dpop_jkt"], proof.Thumbprint);
        Assert.Contains("The token endpoint returned HTTP 401: invalid_client", await HomePageAsync(client));
    }

    [Theory]
    [InlineData("/Account/Introspect", Fault.IntrospectWithoutClientAuthentication, StubIdentify.IntrospectionEndpoint)]
    [InlineData("/Account/Revoke", Fault.RevokeWithoutClientAuthentication, StubIdentify.RevocationEndpoint)]
    [InlineData("/Account/Refresh", Fault.RefreshWithoutClientAuthentication, StubIdentify.TokenEndpoint)]
    public async Task TheFaultsWithoutClientAuthenticationNeedAClientThatAuthenticates(string path, Fault fault, string endpoint)
    {
        var settings = Settings(dpop: true);
        settings["OpenIdConnectOptions:TokenAuthnMethod"] = "none";
        using var factory = new TestWebApplicationFactory(settings: settings);
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);
        var requestsBefore = factory.Identify.RequestsTo(endpoint).Count;

        using var response = await SignInFlow.PostFormAsync(client, path, WithFault(fault));

        Assert.Contains($"The fault {fault} needs a client that authenticates: TokenAuthnMethod none sends no client authentication anyway.", await HomePageAsync(client));
        Assert.Equal(requestsBefore, factory.Identify.RequestsTo(endpoint).Count);
    }

    [Fact]
    public async Task TheNewFaultsAreShownInTheirForms()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);

        var anonymousPage = await client.GetStringAsync("/");
        foreach (var fault in new[] { Fault.ProofWithoutHtm, Fault.ProofWithoutHtu, Fault.ProofWithoutIat, Fault.ReplayParAssertionAtToken, Fault.AssertionNbfFuture })
        {
            Assert.Contains($"<option value=\"{fault}\">{fault}: " + FaultInjection.Describe(fault), WebUtility.HtmlDecode(anonymousPage));
        }

        await SignInFlow.SignInAsync(client, factory);
        var page = await client.GetStringAsync("/");
        foreach (var fault in new[]
        {
            Fault.UserInfoProofAlgNone, Fault.UserInfoProofSignatureOtherKey, Fault.UserInfoProofWithoutJti, Fault.UserInfoProofIatOld,
            Fault.AccessTokenInQuery, Fault.IntrospectWithoutClientAuthentication, Fault.RevokeWithoutClientAuthentication,
            Fault.RefreshWithoutClientAuthentication
        })
        {
            Assert.Contains($"value=\"{fault}\"", page);
            Assert.NotEqual(string.Empty, FaultInjection.Describe(fault));
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

        using var userInfoResponse = await SignInFlow.PostFormAsync(client, "/Account/UserInfo", WithFault(Fault.AccessTokenInQuery));
        using var refreshResponse = await SignInFlow.PostFormAsync(client, "/Account/Refresh", WithFault(Fault.RefreshWithoutClientAuthentication));

        var userInfo = factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint).Last();
        Assert.Equal("DPoP " + accessToken, userInfo.Header("Authorization"));
        Assert.Equal(string.Empty, userInfo.Query);
        Assert.Equal(TestWebApplicationFactory.ClientSecret, factory.Identify.RequestsTo(StubIdentify.TokenEndpoint).Last().Form["client_secret"]);
    }
}
