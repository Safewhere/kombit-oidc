using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace WebAppNetCore.Tests;

public sealed class CodeFlowTests
{
    [Fact]
    public async Task CodeFlowWithClientSecretPostSignsInAndShowsTheTokens()
    {
        using var factory = new TestWebApplicationFactory();
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.SignInAsync(client, factory);

        var tokenRequest = Assert.Single(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint));
        Assert.Equal(HttpMethod.Post, tokenRequest.Method);
        Assert.Equal("authorization_code", tokenRequest.Form["grant_type"]);
        Assert.Equal(SignInFlow.Code, tokenRequest.Form["code"]);
        Assert.Equal("https://localhost/signin-oidc", tokenRequest.Form["redirect_uri"]);
        Assert.Equal(TestWebApplicationFactory.ClientId, tokenRequest.Form["client_id"]);
        Assert.Equal(TestWebApplicationFactory.ClientSecret, tokenRequest.Form["client_secret"]);
        Assert.Null(tokenRequest.Header("Authorization"));
        Assert.Equal(request.Parameters["code_challenge"], CodeChallenge(tokenRequest.Form["code_verifier"]));

        var home = await client.GetStringAsync("/");
        Assert.Contains("Id Token", home);
        Assert.Contains("Access Token", home);
    }

    [Fact]
    public async Task ClientSecretBasicSendsTheCredentialsInTheAuthorizationHeader()
    {
        using var factory = new TestWebApplicationFactory(settings: new Dictionary<string, string?>
        {
            ["OpenIdConnectOptions:TokenAuthnMethod"] = "client_secret_basic"
        });
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInFlow.SignInAsync(client, factory);

        var tokenRequest = Assert.Single(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint));
        var authorization = AuthenticationHeaderValue.Parse(tokenRequest.Header("Authorization")!);
        Assert.Equal("Basic", authorization.Scheme);
        Assert.Equal(
            $"{TestWebApplicationFactory.ClientId}:{TestWebApplicationFactory.ClientSecret}",
            Encoding.UTF8.GetString(Convert.FromBase64String(authorization.Parameter!)));
        Assert.False(tokenRequest.Form.ContainsKey("client_secret"));
    }

    [Fact]
    public async Task PrivateKeyJwtSendsASignedClientAssertionForTheTokenEndpoint()
    {
        using var certificate = new TestCertificateFile();
        using var factory = new TestWebApplicationFactory(settings: certificate.PrivateKeyJwtSettings());
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInFlow.SignInAsync(client, factory);

        var tokenRequest = Assert.Single(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint));
        Assert.Equal("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", tokenRequest.Form["client_assertion_type"]);
        Assert.Equal(TestWebApplicationFactory.ClientId, tokenRequest.Form["client_id"]);
        Assert.False(tokenRequest.Form.ContainsKey("client_secret"));

        var assertion = await ValidateClientAssertionAsync(tokenRequest.Form["client_assertion"], certificate);
        Assert.Equal(SecurityAlgorithms.RsaSha256, assertion.Alg);
        Assert.Equal(Base64UrlEncoder.Encode(certificate.PublicCertificate.GetCertHash()), assertion.Kid);
        Assert.Equal(TestWebApplicationFactory.ClientId, assertion.Issuer);
        Assert.Equal(TestWebApplicationFactory.ClientId, assertion.Subject);
        Assert.Equal(StubIdentify.TokenEndpoint, assertion.GetPayloadValue<string>("aud"));
        Assert.False(string.IsNullOrEmpty(assertion.Id));
    }

    [Fact]
    public async Task TheTokenEndpointComesFromTheDiscoveryDocument()
    {
        using var factory = new TestWebApplicationFactory();
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInFlow.SignInAsync(client, factory);

        Assert.Single(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint));
    }

    [Fact]
    public async Task ATokenErrorResponseIsShownOnTheErrorPage()
    {
        using var factory = new TestWebApplicationFactory();
        factory.Identify.TokenResponder = _ => StubIdentify.OAuthError(HttpStatusCode.BadRequest, "invalid_grant", "The code is not valid.");
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.StartAsync(client, factory);
        using var callback = await SignInFlow.CompleteAsync(client, factory, request);

        var errorPage = await SignInFlow.AssertErrorPageAsync(client, callback);
        Assert.Contains("The token endpoint returned HTTP 400: invalid_grant (The code is not valid.)", errorPage);
    }

    [Fact]
    public async Task AnIdTokenWithAnotherNonceIsRejected()
    {
        using var factory = new TestWebApplicationFactory();
        using var client = SignInFlow.CreateHttpsClient(factory);
        var request = await SignInFlow.StartAsync(client, factory);
        factory.Identify.Nonce = "another-nonce";

        using var callback = await client.GetAsync(QueryHelpers.AddQueryString("/signin-oidc", new Dictionary<string, string?>
        {
            ["code"] = SignInFlow.Code,
            ["state"] = request.Parameters["state"]
        }));

        var errorPage = await SignInFlow.AssertErrorPageAsync(client, callback);
        Assert.Contains("nonce", errorPage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ADiscoveryDocumentOfAnotherIssuerStopsTheSignIn()
    {
        using var factory = new TestWebApplicationFactory(settings: new Dictionary<string, string?>
        {
            ["OpenIdConnectOptions:ClaimsIssuer"] = "https://other.test/runtime/oauth2"
        });
        using var client = SignInFlow.CreateHttpsClient(factory);

        using var response = await SignInFlow.PostSignInAsync(client);

        var errorPage = await SignInFlow.AssertErrorPageAsync(client, response);
        Assert.Contains(
            $"The issuer &#x27;{StubIdentify.Issuer}&#x27; in the discovery document differs from the configured issuer &#x27;https://other.test/runtime/oauth2&#x27;.",
            errorPage);
        Assert.Empty(factory.Identify.Requests);
    }

    [Fact]
    public async Task TheNonceHas43Characters()
    {
        using var factory = new TestWebApplicationFactory();
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.StartAsync(client, factory);

        Assert.Matches("^[A-Za-z0-9_-]{43}$", request.Parameters["nonce"]);
    }

    [Fact]
    public async Task AnIdTokenWithAnAlgorithmThatIsNotAllowedIsRejected()
    {
        using var factory = new TestWebApplicationFactory(settings: new Dictionary<string, string?>
        {
            ["OpenIdConnectOptions:ValidIdTokenSigningAlgorithms"] = "PS256"
        });
        using var client = SignInFlow.CreateHttpsClient(factory);
        var request = await SignInFlow.StartAsync(client, factory);

        using var callback = await SignInFlow.CompleteAsync(client, factory, request);

        var errorPage = await SignInFlow.AssertErrorPageAsync(client, callback);
        Assert.Contains("RS256", errorPage);
    }

    [Fact]
    public async Task AnIdTokenWithAnAllowedAlgorithmIsAccepted()
    {
        using var factory = new TestWebApplicationFactory(settings: new Dictionary<string, string?>
        {
            ["OpenIdConnectOptions:ValidIdTokenSigningAlgorithms"] = "PS256"
        });
        factory.Identify.TokenSigningAlgorithm = SecurityAlgorithms.RsaSsaPssSha256;
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInFlow.SignInAsync(client, factory);
    }

    [Fact]
    public async Task TheSampleCallsUserInfoWithTheBearerSchemeAndAddsTheClaims()
    {
        using var factory = new TestWebApplicationFactory();
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInFlow.SignInAsync(client, factory);

        var userInfoRequest = Assert.Single(factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint));
        Assert.Equal(HttpMethod.Get, userInfoRequest.Method);
        var session = await TestSession.GetAsync(client);
        Assert.Equal($"Bearer {session.Tokens["access_token"]}", userInfoRequest.Header("Authorization"));
        Assert.Equal("user@provider.test", session.Claim("email"));
    }

    [Fact]
    public async Task ASignedUserInfoResponseIsRead()
    {
        using var factory = new TestWebApplicationFactory();
        factory.Identify.UserInfoResponder = _ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                factory.Identify.IssueToken(new Dictionary<string, object> { ["sub"] = StubIdentify.Subject, ["email"] = "signed@provider.test" }),
                Encoding.UTF8,
                "application/jwt")
        };
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInFlow.SignInAsync(client, factory);

        Assert.Equal("signed@provider.test", (await TestSession.GetAsync(client)).Claim("email"));
        var page = WebUtility.HtmlDecode(await client.GetStringAsync("/"));
        Assert.Contains("UserInfo request: HTTP 200: application/jwt", page);
        Assert.Matches("<td>Signed UserInfo response</td><td><pre>header: \\{\\s*\"alg\": \"RS256\",\\s*\"kid\": \"stub-signing-key\"[^<]*\"email\": \"signed@provider.test\"", page);
    }

    [Fact]
    public async Task AUserInfoResponseForAnotherSubjectIsRejected()
    {
        using var factory = new TestWebApplicationFactory();
        factory.Identify.UserInfoResponder = _ => StubIdentify.Json(HttpStatusCode.OK, new Dictionary<string, object> { ["sub"] = "someone-else" });
        using var client = SignInFlow.CreateHttpsClient(factory);
        var request = await SignInFlow.StartAsync(client, factory);

        using var callback = await SignInFlow.CompleteAsync(client, factory, request);

        var errorPage = await SignInFlow.AssertErrorPageAsync(client, callback);
        Assert.Contains("someone-else", errorPage);
    }

    [Fact]
    public async Task ConcurrentSignInsKeepTheirOwnTokens()
    {
        using var factory = new TestWebApplicationFactory();
        var clients = Enumerable.Range(0, 20).Select(_ => SignInFlow.CreateHttpsClient(factory)).ToList();
        try
        {
            var requests = new List<AuthorizationRequest>();
            foreach (var client in clients)
            {
                requests.Add(await SignInFlow.StartAsync(client, factory));
            }

            // All callbacks run at the same time: the token responses, the session state, and the back-channel logout record of
            // one sign-in must not reach another sign-in.
            await Task.WhenAll(clients.Select(async (client, i) =>
            {
                using var callback = await SignInFlow.CompleteAsync(client, factory, requests[i], code: $"code-{i}");
                await SignInFlow.AssertSignedInAsync(client, callback);
            }));

            for (var i = 0; i < clients.Count; i++)
            {
                var session = await TestSession.GetAsync(clients[i]);
                Assert.Equal(factory.Identify.AccessTokensByCode[$"code-{i}"], session.Tokens["access_token"]);
                Assert.Equal($"session-code-{i}", session.Claim("sid"));
            }
        }
        finally
        {
            clients.ForEach(c => c.Dispose());
        }
    }

    internal static string CodeChallenge(string codeVerifier)
    {
        return WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)));
    }

    internal static async Task<JsonWebToken> ValidateClientAssertionAsync(string clientAssertion, TestCertificateFile certificate)
    {
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(clientAssertion, new TokenValidationParameters
        {
            IssuerSigningKey = new X509SecurityKey(certificate.PublicCertificate),
            ValidateIssuer = false,
            ValidateAudience = false
        });
        Assert.True(result.IsValid, result.Exception?.Message);
        return (JsonWebToken)result.SecurityToken;
    }
}
