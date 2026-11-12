using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace SampleApi.Tests;

/// <summary>
/// The checks of the contract of the sample resource server (docs/features/US38464/sample-resource-server-contract.md, sections 6
/// and 7), one test for each rejection and a valid read and write.
/// </summary>
public sealed class ProtectedResourceTests : IDisposable
{
    private const string ProfilePath = "/api/profile";
    private const string NotesPath = "/api/notes";
    private const string Challenge = "DPoP algs=\"PS256\"";

    private readonly SampleApiFactory factory = new();
    private readonly RSA proofKey = RSA.Create(2048);
    private readonly RSA otherKey = RSA.Create(2048);

    public void Dispose()
    {
        factory.Dispose();
        proofKey.Dispose();
        otherKey.Dispose();
    }

    private string Jkt => DPoPProofBuilder.Thumbprint(proofKey);

    private string IssueToken(string scope = StubIdentify.AllScopes) => factory.Identify.IssueAccessToken(Jkt, scope);

    private string Proof(string method, string path, string accessToken) => new DPoPProofBuilder(proofKey, method, path, accessToken).Build();

    private static async Task AssertRejectedAsync(HttpResponseMessage response, HttpStatusCode status, string error)
    {
        Assert.Equal(status, response.StatusCode);
        Assert.Equal($"DPoP error=\"{error}\", algs=\"PS256\"", response.Headers.WwwAuthenticate.ToString());
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(error, body.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task AValidReadReturnsTheProfileAndIntrospectsWithTheClientAssertionOfTheApi()
    {
        var token = IssueToken();

        using var response = await factory.SendAsync(HttpMethod.Get, ProfilePath, token, Proof("GET", ProfilePath, token));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(StubIdentify.Subject, body.RootElement.GetProperty("sub").GetString());
        Assert.Equal(StubIdentify.ClientId, body.RootElement.GetProperty("client_id").GetString());
        Assert.Equal(StubIdentify.AllScopes, body.RootElement.GetProperty("scope").GetString());
        Assert.Equal("DPoP", body.RootElement.GetProperty("binding").GetProperty("type").GetString());
        Assert.Equal(Jkt, body.RootElement.GetProperty("binding").GetProperty("jkt").GetString());

        var introspection = Assert.Single(factory.Identify.IntrospectionRequests);
        Assert.Equal(token, introspection["token"]);
        Assert.Equal("access_token", introspection["token_type_hint"]);
        Assert.Equal(SampleApiFactory.ApiClientId, introspection["client_id"]);
        Assert.Equal("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", introspection["client_assertion_type"]);
        var assertion = new JsonWebToken(introspection["client_assertion"]);
        Assert.Equal("PS256", assertion.Alg);
        Assert.Equal(Base64UrlEncoder.Encode(factory.AssertionCertificate.GetCertHash()), assertion.Kid);
        Assert.Equal(SampleApiFactory.ApiClientId, assertion.Issuer);
        Assert.Equal(SampleApiFactory.ApiClientId, assertion.Subject);
        Assert.Equal(StubIdentify.Issuer, Assert.Single(assertion.Audiences));
        var signature = await new JsonWebTokenHandler().ValidateTokenAsync(assertion, new TokenValidationParameters
        {
            IssuerSigningKey = new X509SecurityKey(factory.AssertionCertificate),
            ValidateIssuer = false,
            ValidateAudience = false
        });
        Assert.True(signature.IsValid);
    }

    [Fact]
    public async Task AValidWriteCreatesTheNote()
    {
        var token = IssueToken();

        using var response = await factory.SendAsync(HttpMethod.Post, NotesPath, token, Proof("POST", NotesPath, token),
            content: JsonContent.Create(new { text = "First note" }));

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("First note", body.RootElement.GetProperty("text").GetString());
    }

    [Fact]
    public async Task ARequestWithoutAnAuthorizationHeaderGetsTheChallengeWithoutAnError()
    {
        using var response = await factory.SendAsync(HttpMethod.Get, ProfilePath, null, null);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(Challenge, response.Headers.WwwAuthenticate.ToString());
        Assert.Empty(factory.Identify.IntrospectionRequests);
    }

    [Fact]
    public async Task AnAccessTokenInTheQueryIsRejected()
    {
        var token = IssueToken();
        var path = ProfilePath + "?access_token=" + Uri.EscapeDataString(token);

        using var response = await factory.SendAsync(HttpMethod.Get, path, null, Proof("GET", ProfilePath, token));

        await AssertRejectedAsync(response, HttpStatusCode.BadRequest, "invalid_request");
        Assert.Empty(factory.Identify.IntrospectionRequests);
    }

    [Fact]
    public async Task AnAccessTokenInTheFormIsRejected()
    {
        var token = IssueToken();
        var form = new FormUrlEncodedContent(new Dictionary<string, string> { ["access_token"] = token, ["text"] = "Note" });

        using var response = await factory.SendAsync(HttpMethod.Post, NotesPath, null, Proof("POST", NotesPath, token), content: form);

        await AssertRejectedAsync(response, HttpStatusCode.BadRequest, "invalid_request");
    }

    [Fact]
    public async Task TheBearerSchemeIsRejected()
    {
        var token = IssueToken();

        using var response = await factory.SendAsync(HttpMethod.Get, ProfilePath, token, Proof("GET", ProfilePath, token), scheme: "Bearer");

        await AssertRejectedAsync(response, HttpStatusCode.Unauthorized, "invalid_token");
        Assert.Empty(factory.Identify.IntrospectionRequests);
    }

    [Fact]
    public async Task TwoDPoPHeadersAreRejected()
    {
        var token = IssueToken();
        using var client = factory.CreateClient();
        var request = new HttpRequestMessage(HttpMethod.Get, ProfilePath);
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("DPoP", token);
        request.Headers.Add("DPoP", new[] { Proof("GET", ProfilePath, token), Proof("GET", ProfilePath, token) });

        using var response = await client.SendAsync(request);

        await AssertRejectedAsync(response, HttpStatusCode.BadRequest, "invalid_request");
    }

    public enum TokenFault
    {
        IdToken,
        OtherAudience,
        OtherIssuer,
        Expired,
        UnknownSigningKey,
        NoConfirmation,
        CertificateBoundOnly,
        CertificateAndDPoPBound,
        JktIsNotAString
    }

    [Theory]
    [InlineData(TokenFault.IdToken)]
    [InlineData(TokenFault.OtherAudience)]
    [InlineData(TokenFault.OtherIssuer)]
    [InlineData(TokenFault.Expired)]
    [InlineData(TokenFault.UnknownSigningKey)]
    [InlineData(TokenFault.NoConfirmation)]
    [InlineData(TokenFault.CertificateBoundOnly)]
    [InlineData(TokenFault.CertificateAndDPoPBound)]
    [InlineData(TokenFault.JktIsNotAString)]
    public async Task AnAccessTokenThatFailsTheTokenChecksIsRejectedWithInvalidToken(TokenFault fault)
    {
        var identify = factory.Identify;
        var token = fault switch
        {
            // An ID token has typ JWT and the client ID as aud.
            TokenFault.IdToken => identify.IssueAccessToken(Jkt, audience: StubIdentify.ClientId, type: "JWT"),
            TokenFault.OtherAudience => identify.IssueAccessToken(Jkt, audience: "urn:other-api"),
            TokenFault.OtherIssuer => identify.IssueAccessToken(Jkt, issuer: "https://other.test/runtime/oauth2"),
            TokenFault.Expired => identify.IssueAccessToken(Jkt, expires: DateTime.UtcNow.AddMinutes(-1)),
            TokenFault.UnknownSigningKey => identify.IssueAccessToken(Jkt, signWithOtherKey: true),
            TokenFault.NoConfirmation => identify.IssueAccessToken(null),
            TokenFault.CertificateBoundOnly => identify.IssueAccessToken(null, confirmation: new() { ["x5t#S256"] = "certificate-hash" }),
            TokenFault.CertificateAndDPoPBound => identify.IssueAccessToken(null, confirmation: new() { ["x5t#S256"] = "certificate-hash", ["jkt"] = Jkt }),
            TokenFault.JktIsNotAString => identify.IssueAccessToken(null, confirmation: new() { ["jkt"] = 42 }),
            _ => throw new ArgumentOutOfRangeException(nameof(fault))
        };

        using var response = await factory.SendAsync(HttpMethod.Get, ProfilePath, token, Proof("GET", ProfilePath, token));

        await AssertRejectedAsync(response, HttpStatusCode.Unauthorized, "invalid_token");
        Assert.Empty(factory.Identify.IntrospectionRequests);
    }

    public enum ProofFault
    {
        Missing,
        OtherKey,
        SignatureOfOtherKey,
        WrongHtm,
        WrongHtu,
        HtuWithOtherHost,
        WrongAth,
        NoAth,
        OldIat,
        FutureIat,
        NoJti,
        WrongTyp,
        AlgorithmRs256,
        PrivateKeyInJwk,
        SmallKey,
        CritHeader
    }

    [Theory]
    [InlineData(ProofFault.Missing)]
    [InlineData(ProofFault.OtherKey)]
    [InlineData(ProofFault.SignatureOfOtherKey)]
    [InlineData(ProofFault.WrongHtm)]
    [InlineData(ProofFault.WrongHtu)]
    [InlineData(ProofFault.HtuWithOtherHost)]
    [InlineData(ProofFault.WrongAth)]
    [InlineData(ProofFault.NoAth)]
    [InlineData(ProofFault.OldIat)]
    [InlineData(ProofFault.FutureIat)]
    [InlineData(ProofFault.NoJti)]
    [InlineData(ProofFault.WrongTyp)]
    [InlineData(ProofFault.AlgorithmRs256)]
    [InlineData(ProofFault.PrivateKeyInJwk)]
    [InlineData(ProofFault.SmallKey)]
    [InlineData(ProofFault.CritHeader)]
    public async Task AProofThatFailsTheProofChecksIsRejectedWithInvalidDPoPProof(ProofFault fault)
    {
        var token = IssueToken();
        using var smallKey = RSA.Create(1024);
        var builder = new DPoPProofBuilder(fault == ProofFault.OtherKey ? otherKey : fault == ProofFault.SmallKey ? smallKey : proofKey, "GET", ProfilePath, token);
        switch (fault)
        {
            case ProofFault.SignatureOfOtherKey:
                builder.SigningKey = otherKey;
                break;
            case ProofFault.WrongHtm:
                builder.Payload["htm"] = "POST";
                break;
            case ProofFault.WrongHtu:
                builder.Payload["htu"] = SampleApiFactory.PublicBaseUrl + NotesPath;
                break;
            case ProofFault.HtuWithOtherHost:
                builder.Payload["htu"] = "https://localhost" + ProfilePath;
                break;
            case ProofFault.WrongAth:
                builder.Payload["ath"] = Base64UrlEncoder.Encode(SHA256.HashData("another token"u8.ToArray()));
                break;
            case ProofFault.NoAth:
                builder.Payload.Remove("ath");
                break;
            case ProofFault.OldIat:
                builder.Payload["iat"] = DateTimeOffset.UtcNow.AddSeconds(-90).ToUnixTimeSeconds();
                break;
            case ProofFault.FutureIat:
                builder.Payload["iat"] = DateTimeOffset.UtcNow.AddSeconds(30).ToUnixTimeSeconds();
                break;
            case ProofFault.NoJti:
                builder.Payload.Remove("jti");
                break;
            case ProofFault.WrongTyp:
                builder.Header["typ"] = "JWT";
                break;
            case ProofFault.AlgorithmRs256:
                builder.Header["alg"] = "RS256";
                break;
            case ProofFault.PrivateKeyInJwk:
                builder.Jwk["d"] = Base64UrlEncoder.Encode(proofKey.ExportParameters(true).D);
                break;
            case ProofFault.CritHeader:
                builder.Header["crit"] = new[] { "exp" };
                break;
        }

        var proof = fault == ProofFault.Missing ? null : builder.Build();

        using var response = await factory.SendAsync(HttpMethod.Get, ProfilePath, token, proof);

        await AssertRejectedAsync(response, HttpStatusCode.Unauthorized, "invalid_dpop_proof");
        Assert.Empty(factory.Identify.IntrospectionRequests);
    }

    [Fact]
    public async Task AReplayedProofIsRejected()
    {
        var token = IssueToken();
        var proof = Proof("GET", ProfilePath, token);

        using var first = await factory.SendAsync(HttpMethod.Get, ProfilePath, token, proof);
        using var second = await factory.SendAsync(HttpMethod.Get, ProfilePath, token, proof);

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        await AssertRejectedAsync(second, HttpStatusCode.Unauthorized, "invalid_dpop_proof");
    }

    [Fact]
    public async Task ARevokedAccessTokenIsRejectedAfterIntrospection()
    {
        var token = IssueToken();
        factory.Identify.RevokedTokens[token] = true;

        using var response = await factory.SendAsync(HttpMethod.Get, ProfilePath, token, Proof("GET", ProfilePath, token));

        await AssertRejectedAsync(response, HttpStatusCode.Unauthorized, "invalid_token");
        Assert.Single(factory.Identify.IntrospectionRequests);
    }

    [Fact]
    public async Task AnIntrospectionResultWithAnotherKeyIsRejected()
    {
        var token = IssueToken();
        factory.Identify.IntrospectionResponder = _ => StubIdentify.Json(HttpStatusCode.OK, new Dictionary<string, object>
        {
            ["active"] = true,
            ["token_type"] = "DPoP",
            ["cnf"] = new Dictionary<string, string> { ["jkt"] = DPoPProofBuilder.Thumbprint(otherKey) }
        });

        using var response = await factory.SendAsync(HttpMethod.Get, ProfilePath, token, Proof("GET", ProfilePath, token));

        await AssertRejectedAsync(response, HttpStatusCode.Unauthorized, "invalid_token");
    }

    [Fact]
    public async Task AnIntrospectionErrorGivesHttp503WithoutAChallenge()
    {
        var token = IssueToken();
        factory.Identify.IntrospectionResponder = _ => new HttpResponseMessage(HttpStatusCode.InternalServerError);

        using var response = await factory.SendAsync(HttpMethod.Get, ProfilePath, token, Proof("GET", ProfilePath, token));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Empty(response.Headers.WwwAuthenticate);
    }

    [Fact]
    public async Task ADiscoveryDocumentOfAnotherIssuerGivesHttp503()
    {
        factory.Identify.DiscoveryIssuer = "https://other.test/runtime/oauth2";
        var token = IssueToken();

        using var response = await factory.SendAsync(HttpMethod.Get, ProfilePath, token, Proof("GET", ProfilePath, token));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Empty(factory.Identify.IntrospectionRequests);
    }

    [Fact]
    public async Task AWriteWithOnlyTheReadScopeIsForbidden()
    {
        var token = IssueToken("openid sample-api.read");

        using var write = await factory.SendAsync(HttpMethod.Post, NotesPath, token, Proof("POST", NotesPath, token),
            content: JsonContent.Create(new { text = "Note" }));
        using var read = await factory.SendAsync(HttpMethod.Get, ProfilePath, token, Proof("GET", ProfilePath, token));

        Assert.Equal(HttpStatusCode.Forbidden, write.StatusCode);
        Assert.Equal("DPoP error=\"insufficient_scope\", scope=\"sample-api.write\", algs=\"PS256\"", write.Headers.WwwAuthenticate.ToString());
        Assert.Equal(HttpStatusCode.OK, read.StatusCode);
    }

    [Fact]
    public async Task ANoteWithATooLongTextIsRejected()
    {
        var token = IssueToken();

        using var response = await factory.SendAsync(HttpMethod.Post, NotesPath, token, Proof("POST", NotesPath, token),
            content: JsonContent.Create(new { text = new string('x', SampleApiEndpoints.MaximumNoteLength + 1) }));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}
