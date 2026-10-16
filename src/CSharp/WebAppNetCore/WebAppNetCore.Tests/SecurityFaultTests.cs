using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WebAppNetCore.OAuth;
using Xunit;

namespace WebAppNetCore.Tests;

/// <summary>
/// The faults for the security negative tests: forged and replayed credentials, credentials of another client, and redirect URIs
/// that only start with the registered one. Each test checks that the fault changes only its target.
/// </summary>
public sealed class SecurityFaultTests
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

    private static RecordedRequest SingleRequestTo(TestWebApplicationFactory factory, string endpoint) =>
        Assert.Single(factory.Identify.RequestsTo(endpoint));

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

    private static string HmacSignature(string jwt, string secret)
    {
        var parts = jwt.Split('.');
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        return Base64UrlEncoder.Encode(hmac.ComputeHash(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1])));
    }

    [Theory]
    [InlineData("client_secret_post")]
    [InlineData("client_secret_basic")]
    [InlineData("private_key_jwt")]
    public async Task ParWithoutClientAuthenticationSendsTheClientIdWithoutCredentials(string method)
    {
        using var certificate = new TestCertificateFile();
        var settings = PrivateKeyJwtSettings(certificate);
        settings["OpenIdConnectOptions:TokenAuthnMethod"] = method;
        using var factory = new TestWebApplicationFactory(settings: settings);
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.StartAsync(client, factory, WithFault(Fault.ParWithoutClientAuthentication));

        var par = SingleRequestTo(factory, StubIdentify.ParEndpoint);
        Assert.Equal(TestWebApplicationFactory.ClientId, par.Form["client_id"]);
        Assert.Null(par.Header("Authorization"));
        foreach (var name in new[] { "client_secret", "client_assertion", "client_assertion_type" })
        {
            Assert.False(par.Form.ContainsKey(name), $"The pushed request has {name}.");
        }

        // The other authorization parameters stay.
        Assert.Equal("S256", request.Parameters["code_challenge_method"]);
    }

    [Theory]
    [InlineData(Fault.ParRedirectUriExtraPath, "https://localhost/signin-oidc/x")]
    [InlineData(Fault.ParRedirectUriExtraQuery, "https://localhost/signin-oidc?x=1")]
    public async Task RedirectUriFaultsChangeOnlyThePushedRedirectUri(Fault fault, string pushedRedirectUri)
    {
        using var factory = new TestWebApplicationFactory(settings: Settings());
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInWithFaultAsync(client, factory, fault);

        Assert.Equal(pushedRedirectUri, SingleRequestTo(factory, StubIdentify.ParEndpoint).Form["redirect_uri"]);
        Assert.Equal("https://localhost/signin-oidc", SingleRequestTo(factory, StubIdentify.TokenEndpoint).Form["redirect_uri"]);
    }

    [Theory]
    [InlineData(Fault.ProofAlgNone)]
    [InlineData(Fault.ProofHmac)]
    [InlineData(Fault.ProofSignatureOtherKey)]
    [InlineData(Fault.ProofWithoutJti)]
    public async Task ProofFaultsForgeOnlyTheTokenProof(Fault fault)
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true, par: false));
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInWithFaultAsync(client, factory, fault);

        var proof = SingleRequestTo(factory, StubIdentify.TokenEndpoint).Header("DPoP")!;
        var header = Part(proof, 0);
        var payload = Part(proof, 1);
        var read = DPoPProof.Read(proof);
        Assert.Equal("dpop+jwt", header.GetProperty("typ").GetString());
        Assert.Equal(request.Parameters["dpop_jkt"], read.Thumbprint);
        Assert.Equal("POST", read.Claim("htm"));
        Assert.Equal(StubIdentify.TokenEndpoint, read.Claim("htu"));
        var jwk = new JsonWebKey(header.GetProperty("jwk").GetRawText());
        switch (fault)
        {
            case Fault.ProofAlgNone:
                Assert.Equal("none", header.GetProperty("alg").GetString());
                Assert.Equal(string.Empty, proof.Split('.')[2]);
                break;
            case Fault.ProofHmac:
                Assert.Equal("HS256", header.GetProperty("alg").GetString());
                Assert.NotEqual(string.Empty, proof.Split('.')[2]);
                Assert.False(await VerifiesWithAsync(proof, jwk));
                break;
            case Fault.ProofSignatureOtherKey:
                Assert.Matches("^(RS|PS)(256|384|512)$", header.GetProperty("alg").GetString());
                Assert.False(await VerifiesWithAsync(proof, jwk), "The proof verifies with its jwk.");
                break;
            case Fault.ProofWithoutJti:
                Assert.False(payload.TryGetProperty("jti", out _), "The proof has jti.");
                Assert.True(await VerifiesWithAsync(proof, jwk));
                break;
        }

        // The UserInfo call of the sign-in has a correct proof.
        var accessToken = (await TestSession.GetAsync(client)).Tokens["access_token"];
        await DPoPProof.ValidateAsync(SingleRequestTo(factory, StubIdentify.UserInfoEndpoint).Header("DPoP"), "GET", StubIdentify.UserInfoEndpoint, accessToken);
    }

    [Theory]
    [InlineData(Fault.AssertionAlgNone)]
    [InlineData(Fault.AssertionHmacWithClientSecret)]
    [InlineData(Fault.AssertionSignedByOtherKey)]
    [InlineData(Fault.AssertionExpired)]
    [InlineData(Fault.AssertionWithoutExp)]
    [InlineData(Fault.AssertionIssuerNotClient)]
    public async Task AssertionFaultsForgeTheAssertionsAtParAndAtTheTokenEndpoint(Fault fault)
    {
        using var certificate = new TestCertificateFile();
        using var factory = new TestWebApplicationFactory(settings: PrivateKeyJwtSettings(certificate));
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInWithFaultAsync(client, factory, fault);

        var clientKey = new X509SecurityKey(certificate.PublicCertificate);
        var kid = Base64UrlEncoder.Encode(certificate.PublicCertificate.GetCertHash());
        foreach (var endpoint in new[] { StubIdentify.ParEndpoint, StubIdentify.TokenEndpoint })
        {
            var form = SingleRequestTo(factory, endpoint).Form;
            var assertion = form["client_assertion"];
            var header = Part(assertion, 0);
            var payload = Part(assertion, 1);
            var now = DateTimeOffset.UtcNow;
            Assert.Equal(TestWebApplicationFactory.ClientId, form["client_id"]);
            Assert.Equal(TestWebApplicationFactory.ClientId, payload.GetProperty("sub").GetString());
            Assert.Equal(StubIdentify.Issuer, payload.GetProperty("aud").GetString());
            Assert.False(string.IsNullOrEmpty(payload.GetProperty("jti").GetString()));
            switch (fault)
            {
                case Fault.AssertionAlgNone:
                    Assert.Equal("none", header.GetProperty("alg").GetString());
                    Assert.Equal(kid, header.GetProperty("kid").GetString());
                    Assert.Equal(string.Empty, assertion.Split('.')[2]);
                    break;
                case Fault.AssertionHmacWithClientSecret:
                    Assert.Equal("HS256", header.GetProperty("alg").GetString());
                    Assert.Equal(HmacSignature(assertion, TestWebApplicationFactory.ClientSecret), assertion.Split('.')[2]);
                    break;
                case Fault.AssertionSignedByOtherKey:
                    Assert.Equal(kid, header.GetProperty("kid").GetString());
                    Assert.False(await VerifiesWithAsync(assertion, clientKey), "The assertion verifies with the client key.");
                    break;
                case Fault.AssertionExpired:
                    Assert.InRange(DateTimeOffset.FromUnixTimeSeconds(payload.GetProperty("exp").GetInt64()), now.AddSeconds(-70), now.AddSeconds(-50));
                    Assert.InRange(DateTimeOffset.FromUnixTimeSeconds(payload.GetProperty("iat").GetInt64()), now.AddSeconds(-130), now.AddSeconds(-110));
                    Assert.False(payload.TryGetProperty("nbf", out _), "The assertion has nbf.");
                    Assert.True(await VerifiesWithAsync(assertion, clientKey));
                    break;
                case Fault.AssertionWithoutExp:
                    Assert.False(payload.TryGetProperty("exp", out _), "The assertion has exp.");
                    Assert.True(payload.TryGetProperty("iat", out _));
                    Assert.True(await VerifiesWithAsync(assertion, clientKey));
                    break;
                case Fault.AssertionIssuerNotClient:
                    Assert.Equal(OtherClientId, payload.GetProperty("iss").GetString());
                    Assert.True(await VerifiesWithAsync(assertion, clientKey));
                    break;
            }

            if (fault != Fault.AssertionIssuerNotClient)
            {
                Assert.Equal(TestWebApplicationFactory.ClientId, payload.GetProperty("iss").GetString());
            }
        }
    }

    [Fact]
    public async Task RedeemAsOtherClientAuthenticatesTheCodeRequestAsTheOtherClientWithTheClientKey()
    {
        using var certificate = new TestCertificateFile();
        using var factory = new TestWebApplicationFactory(settings: PrivateKeyJwtSettings(certificate, dpop: true));
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInWithFaultAsync(client, factory, Fault.RedeemAsOtherClient);

        // The pushed request is of this client; only the token request is of the other one.
        var par = SingleRequestTo(factory, StubIdentify.ParEndpoint);
        Assert.Equal(TestWebApplicationFactory.ClientId, par.Form["client_id"]);
        Assert.Equal(TestWebApplicationFactory.ClientId, Part(par.Form["client_assertion"], 1).GetProperty("iss").GetString());

        var token = SingleRequestTo(factory, StubIdentify.TokenEndpoint);
        Assert.Equal(OtherClientId, token.Form["client_id"]);
        var assertion = await CodeFlowTests.ValidateClientAssertionAsync(token.Form["client_assertion"], certificate);
        Assert.Equal(OtherClientId, assertion.Issuer);
        Assert.Equal(OtherClientId, assertion.Subject);
        Assert.Equal(SignInFlow.Code, token.Form["code"]);
        Assert.True(token.Form.ContainsKey("code_verifier"));
        await DPoPProof.ValidateAsync(token.Header("DPoP"), "POST", StubIdentify.TokenEndpoint);
        Assert.Equal(request.Parameters["dpop_jkt"], DPoPProof.Read(token.Header("DPoP")!).Thumbprint);
    }

    [Fact]
    public async Task AFaultOfTheOtherClientFailsWithAMessageWithoutTheSetting()
    {
        using var certificate = new TestCertificateFile();
        var settings = PrivateKeyJwtSettings(certificate);
        settings.Remove("Testing:OtherClientId");
        using var factory = new TestWebApplicationFactory(settings: settings);
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.StartAsync(client, factory, WithFault(Fault.RedeemAsOtherClient));
        using var callback = await SignInFlow.CompleteAsync(client, factory, request);

        var errorPage = await SignInFlow.AssertErrorPageAsync(client, callback);
        Assert.Contains("The fault needs the client ID of another client in Testing:OtherClientId.", WebUtility.HtmlDecode(errorPage));
        Assert.Empty(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint));
    }

    [Fact]
    public async Task MissingCodeVerifierOmitsTheCodeVerifier()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings());
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInWithFaultAsync(client, factory, Fault.MissingCodeVerifier);

        Assert.False(string.IsNullOrEmpty(request.Parameters["code_challenge"]));
        var token = SingleRequestTo(factory, StubIdentify.TokenEndpoint);
        Assert.False(token.Form.ContainsKey("code_verifier"), "The token request has code_verifier.");
        Assert.Equal(SignInFlow.Code, token.Form["code"]);
    }

    [Fact]
    public async Task TokenRedirectUriMismatchSendsAnotherPathOfTheSameOrigin()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings());
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInWithFaultAsync(client, factory, Fault.TokenRedirectUriMismatch);

        Assert.Equal("https://localhost/signin-oidc", request.Parameters["redirect_uri"]);
        Assert.Equal("https://localhost/other-callback", SingleRequestTo(factory, StubIdentify.TokenEndpoint).Form["redirect_uri"]);
    }

    [Theory]
    [InlineData(Fault.UserInfoProofOtherKey)]
    [InlineData(Fault.UserInfoProofWrongHtm)]
    [InlineData(Fault.UserInfoProofWrongHtu)]
    [InlineData(Fault.UserInfoProofWrongAth)]
    public async Task UserInfoProofFaultsChangeOnlyTheirClaimOrKey(Fault fault)
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true, par: false));
        using var client = SignInFlow.CreateHttpsClient(factory);
        var request = await SignInFlow.SignInAsync(client, factory);
        var accessToken = (await TestSession.GetAsync(client)).Tokens["access_token"];

        using var response = await SignInFlow.PostFormAsync(client, "/Account/UserInfo", WithFault(fault));

        var userInfo = factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint).Last();
        Assert.Equal("DPoP " + accessToken, userInfo.Header("Authorization"));
        var (htm, htu, ath) = fault switch
        {
            Fault.UserInfoProofWrongHtm => ("POST", StubIdentify.UserInfoEndpoint, accessToken),
            Fault.UserInfoProofWrongHtu => ("GET", StubIdentify.TokenEndpoint, accessToken),
            Fault.UserInfoProofWrongAth => ("GET", StubIdentify.UserInfoEndpoint, accessToken + "-other"),
            _ => ("GET", StubIdentify.UserInfoEndpoint, accessToken)
        };
        var proof = await DPoPProof.ValidateAsync(userInfo.Header("DPoP"), htm, htu, ath);
        if (fault == Fault.UserInfoProofOtherKey)
        {
            Assert.NotEqual(request.Parameters["dpop_jkt"], proof.Thumbprint);
        }
        else
        {
            Assert.Equal(request.Parameters["dpop_jkt"], proof.Thumbprint);
        }
    }

    [Fact]
    public async Task ReplayDPoPProofOnRefreshSendsTheSameProofInTwoRefreshRequests()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(dpop: true, par: false));
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);
        factory.Identify.TokenResponder = recorded => factory.Identify.RequestsTo(StubIdentify.TokenEndpoint).Count > 2
            ? StubIdentify.OAuthError(HttpStatusCode.BadRequest, "invalid_dpop_proof", "The DPoP proof was used before.")
            : factory.Identify.DefaultTokenResponse(recorded);

        using var response = await SignInFlow.PostFormAsync(client, "/Account/Refresh", WithFault(Fault.ReplayDPoPProofOnRefresh));
        var page = WebUtility.HtmlDecode(await client.GetStringAsync("/"));

        var requests = factory.Identify.RequestsTo(StubIdentify.TokenEndpoint);
        Assert.Equal(3, requests.Count);
        Assert.All(requests.Skip(1), r => Assert.Equal("refresh_token", r.Form["grant_type"]));
        Assert.Equal(requests[1].Header("DPoP"), requests[2].Header("DPoP"));
        Assert.NotEqual(requests[0].Header("DPoP"), requests[1].Header("DPoP"));
        Assert.Contains("The token endpoint returned HTTP 400: invalid_dpop_proof", page);
        Assert.Contains("ReplayDPoPProofOnRefresh: the next refresh request sends the same proof", page);
    }

    [Fact]
    public async Task RefreshAsOtherClientAuthenticatesTheRefreshAsTheOtherClientWithTheClientKey()
    {
        using var certificate = new TestCertificateFile();
        using var factory = new TestWebApplicationFactory(settings: PrivateKeyJwtSettings(certificate));
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);

        using var response = await SignInFlow.PostFormAsync(client, "/Account/Refresh", WithFault(Fault.RefreshAsOtherClient));

        var requests = factory.Identify.RequestsTo(StubIdentify.TokenEndpoint);
        Assert.Equal(TestWebApplicationFactory.ClientId, requests[0].Form["client_id"]);
        var refresh = requests.Last();
        Assert.Equal("refresh_token", refresh.Form["grant_type"]);
        Assert.Equal(StubIdentify.RefreshToken, refresh.Form["refresh_token"]);
        Assert.Equal(OtherClientId, refresh.Form["client_id"]);
        var assertion = await CodeFlowTests.ValidateClientAssertionAsync(refresh.Form["client_assertion"], certificate);
        Assert.Equal(OtherClientId, assertion.Issuer);
        Assert.Equal(OtherClientId, assertion.Subject);
    }

    [Fact]
    public async Task ReuseRotatedRefreshTokenSendsTheOldTokenAndKeepsTheNewOne()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(par: false));
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);
        // Like a connection that rotates: each refresh returns a new refresh token, and a used one is rejected.
        var used = new HashSet<string>();
        var issued = 1;
        factory.Identify.TokenResponder = recorded =>
        {
            var refreshToken = recorded.Form.GetValueOrDefault("refresh_token");
            if (refreshToken == null)
            {
                return factory.Identify.DefaultTokenResponse(recorded);
            }

            if (!used.Add(refreshToken))
            {
                return StubIdentify.OAuthError(HttpStatusCode.BadRequest, "invalid_grant", "The refresh token is not valid.");
            }

            return StubIdentify.Json(HttpStatusCode.OK, new Dictionary<string, object>
            {
                ["access_token"] = factory.Identify.IssueAccessToken(),
                ["token_type"] = "Bearer",
                ["expires_in"] = 300,
                ["refresh_token"] = "refresh-token-" + ++issued
            });
        };

        using var faultResponse = await SignInFlow.PostFormAsync(client, "/Account/Refresh", WithFault(Fault.ReuseRotatedRefreshToken));
        var page = WebUtility.HtmlDecode(await client.GetStringAsync("/"));
        using var nextResponse = await SignInFlow.PostFormAsync(client, "/Account/Refresh");
        var nextPage = WebUtility.HtmlDecode(await client.GetStringAsync("/"));

        var refreshTokens = factory.Identify.RequestsTo(StubIdentify.TokenEndpoint).Skip(1).Select(r => r.Form["refresh_token"]).ToList();
        Assert.Equal(new[] { StubIdentify.RefreshToken, StubIdentify.RefreshToken, "refresh-token-2" }, refreshTokens);
        Assert.Contains("The token endpoint returned HTTP 400: invalid_grant (The refresh token is not valid.)", page);
        Assert.Contains("ReuseRotatedRefreshToken: the next refresh request sends the old refresh token", page);
        Assert.Contains("Identify returned a new refresh token, and the sample stored it.", nextPage);
    }

    [Fact]
    public async Task ReuseRotatedRefreshTokenStopsWhenTheRefreshTokenIsNotRotated()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(par: false));
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);

        using var response = await SignInFlow.PostFormAsync(client, "/Account/Refresh", WithFault(Fault.ReuseRotatedRefreshToken));
        var page = WebUtility.HtmlDecode(await client.GetStringAsync("/"));

        Assert.Equal(2, factory.Identify.RequestsTo(StubIdentify.TokenEndpoint).Count);
        Assert.Contains("Identify returned no new refresh token, so there is no old one to send.", page);
    }
}
