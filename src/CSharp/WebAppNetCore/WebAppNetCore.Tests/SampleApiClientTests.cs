using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using WebAppNetCore.OAuth;
using Xunit;

namespace WebAppNetCore.Tests;

/// <summary>
/// A sample resource server that records the requests of the client and returns a fixed response.
/// </summary>
internal sealed class StubSampleApi : HttpMessageHandler
{
    internal const string BaseUrl = "https://api.test";

    internal ConcurrentQueue<(RecordedRequest Request, string Body)> Requests { get; } = new();

    internal Func<HttpResponseMessage>? Responder { get; set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
        Requests.Enqueue((await RecordedRequest.CreateAsync(request), body));
        return Responder?.Invoke() ?? new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{\"sub\":\"" + StubIdentify.Subject + "\"}", Encoding.UTF8, "application/json")
        };
    }
}

/// <summary>
/// The calls of the sample resource server (docs/features/US38464/sample-resource-server-contract.md section 10).
/// </summary>
public sealed class SampleApiClientTests
{
    private static Dictionary<string, string?> Settings(string? scopes = null)
    {
        var settings = new Dictionary<string, string?>
        {
            ["Testing:EnableFaultInjection"] = "true",
            ["OpenIdConnectOptions:DPoP:BindAccessTokens"] = "true",
            ["OpenIdConnectOptions:DPoP:SendDPoPJkt"] = "true",
            ["SampleApi:BaseUrl"] = StubSampleApi.BaseUrl + "/"
        };
        if (scopes is not null)
        {
            settings["SampleApi:Scopes"] = scopes;
        }

        return settings;
    }

    private static Dictionary<string, string> WithFault(Fault fault) => new() { [FaultInjection.FieldName] = fault.ToString() };

    private static string Ath(string token) => Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(token)));

    private static string Thumbprint(JsonWebToken proof)
    {
        using var header = JsonDocument.Parse(Base64UrlEncoder.Decode(proof.EncodedHeader));
        return Base64UrlEncoder.Encode(new JsonWebKey(header.RootElement.GetProperty("jwk").GetRawText()).ComputeJwkThumbprint());
    }

    private static string AccessTokenJkt(string accessToken)
    {
        using var payload = JsonDocument.Parse(Base64UrlEncoder.Decode(new JsonWebToken(accessToken).EncodedPayload));
        return payload.RootElement.GetProperty("cnf").GetProperty("jkt").GetString()!;
    }

    [Fact]
    public async Task TheSignInRequestsTheScopesOfTheSampleApi()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings());
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.StartAsync(client, factory);

        Assert.Equal("openid sample-api.read sample-api.write", request.Parameters["scope"]);
    }

    [Fact]
    public async Task SampleApiScopesReplacesTheScopesOfTheSampleApi()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(scopes: "sample-api.read"));
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.StartAsync(client, factory);

        Assert.Equal("openid sample-api.read", request.Parameters["scope"]);
    }

    [Fact]
    public async Task WithoutABaseUrlTheHomePageHasNoSampleApiButtonsAndTheSignInNoApiScope()
    {
        var settings = Settings();
        settings["SampleApi:BaseUrl"] = string.Empty;
        using var factory = new TestWebApplicationFactory(settings: settings);
        using var client = SignInFlow.CreateHttpsClient(factory);

        var request = await SignInFlow.SignInAsync(client, factory);
        var page = await client.GetStringAsync("/");

        Assert.Equal("openid", request.Parameters["scope"]);
        Assert.DoesNotContain("Call sample API", page);
    }

    [Fact]
    public async Task CallSampleApiSendsTheAccessTokenWithTheDPoPSchemeAndAProofOfTheKeyOfTheSignIn()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings());
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);
        var accessToken = (await TestSession.GetAsync(client)).Tokens["access_token"];

        using var response = await SignInFlow.PostFormAsync(client, "/Account/CallSampleApi");
        var page = WebUtility.HtmlDecode(await client.GetStringAsync("/"));

        var (request, _) = Assert.Single(factory.SampleApi.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal(StubSampleApi.BaseUrl + SampleApiClient.ProfilePath, request.Url);
        Assert.Equal("DPoP " + accessToken, request.Header("Authorization"));
        var proof = new JsonWebToken(request.Header("DPoP")!);
        Assert.Equal("dpop+jwt", proof.Typ);
        Assert.Equal("GET", proof.GetPayloadValue<string>("htm"));
        Assert.Equal(StubSampleApi.BaseUrl + SampleApiClient.ProfilePath, proof.GetPayloadValue<string>("htu"));
        Assert.Equal(Ath(accessToken), proof.GetPayloadValue<string>("ath"));
        Assert.Equal(AccessTokenJkt(accessToken), Thumbprint(proof));
        Assert.Contains("The sample API returned HTTP 200: {\"sub\":\"" + StubIdentify.Subject + "\"}", page);
        Assert.Contains("Sample API request: HTTP 200", page);
    }

    [Fact]
    public async Task WriteNoteSendsTheTextAsJsonWithAProofForPost()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings());
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);

        using var response = await SignInFlow.PostFormAsync(client, "/Account/WriteNote", new Dictionary<string, string> { ["text"] = "Hello" });

        var (request, body) = Assert.Single(factory.SampleApi.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal(StubSampleApi.BaseUrl + SampleApiClient.NotesPath, request.Url);
        Assert.Equal("{\"text\":\"Hello\"}", body);
        var proof = new JsonWebToken(request.Header("DPoP")!);
        Assert.Equal("POST", proof.GetPayloadValue<string>("htm"));
        Assert.Equal(StubSampleApi.BaseUrl + SampleApiClient.NotesPath, proof.GetPayloadValue<string>("htu"));
    }

    [Fact]
    public async Task AnErrorOfTheSampleApiShowsTheErrorAndTheChallenge()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings());
        factory.SampleApi.Responder = () =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.Unauthorized)
            {
                Content = new StringContent("{\"error\":\"invalid_token\",\"error_description\":\"The access token is not valid.\"}", Encoding.UTF8, "application/json")
            };
            response.Headers.WwwAuthenticate.ParseAdd("DPoP error=\"invalid_token\", algs=\"PS256\"");
            return response;
        };
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);

        using var response = await SignInFlow.PostFormAsync(client, "/Account/CallSampleApi");
        var page = WebUtility.HtmlDecode(await client.GetStringAsync("/"));

        Assert.Contains("The sample API returned HTTP 401: invalid_token (The access token is not valid.)", page);
        Assert.Contains("DPoP error=\"invalid_token\", algs=\"PS256\"", page);
    }

    [Theory]
    [InlineData(Fault.SampleApiBearerScheme)]
    [InlineData(Fault.SampleApiTokenInQuery)]
    [InlineData(Fault.SampleApiIdToken)]
    [InlineData(Fault.SampleApiProofOtherKey)]
    [InlineData(Fault.SampleApiReplayProof)]
    [InlineData(Fault.SampleApiProofWrongHtm)]
    [InlineData(Fault.SampleApiProofWrongHtu)]
    [InlineData(Fault.SampleApiProofWrongAth)]
    public async Task EachSampleApiFaultChangesOnlyItsPartOfTheRequest(Fault fault)
    {
        using var factory = new TestWebApplicationFactory(settings: Settings());
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);
        var tokens = (await TestSession.GetAsync(client)).Tokens;
        var accessToken = tokens["access_token"];

        using var response = await SignInFlow.PostFormAsync(client, "/Account/CallSampleApi", WithFault(fault));

        var requests = factory.SampleApi.Requests.Select(entry => entry.Request).ToList();
        var request = requests.Last();
        var proof = request.Header("DPoP") is { } value ? new JsonWebToken(value) : null;
        switch (fault)
        {
            case Fault.SampleApiBearerScheme:
                Assert.Equal("Bearer " + accessToken, request.Header("Authorization"));
                Assert.Null(proof);
                break;
            case Fault.SampleApiTokenInQuery:
                Assert.Null(request.Header("Authorization"));
                Assert.Equal("?access_token=" + Uri.EscapeDataString(accessToken), request.Query);
                Assert.Equal(Ath(accessToken), proof!.GetPayloadValue<string>("ath"));
                break;
            case Fault.SampleApiIdToken:
                Assert.Equal("DPoP " + tokens["id_token"], request.Header("Authorization"));
                Assert.Equal(Ath(tokens["id_token"]), proof!.GetPayloadValue<string>("ath"));
                break;
            case Fault.SampleApiProofOtherKey:
                Assert.NotEqual(AccessTokenJkt(accessToken), Thumbprint(proof!));
                break;
            case Fault.SampleApiReplayProof:
                Assert.Equal(2, requests.Count);
                Assert.Equal(requests[0].Header("DPoP"), requests[1].Header("DPoP"));
                break;
            case Fault.SampleApiProofWrongHtm:
                Assert.Equal(HttpMethod.Get, request.Method);
                Assert.Equal("POST", proof!.GetPayloadValue<string>("htm"));
                break;
            case Fault.SampleApiProofWrongHtu:
                Assert.Equal(StubSampleApi.BaseUrl + SampleApiClient.NotesPath, proof!.GetPayloadValue<string>("htu"));
                break;
            case Fault.SampleApiProofWrongAth:
                Assert.NotEqual(Ath(accessToken), proof!.GetPayloadValue<string>("ath"));
                Assert.Equal(AccessTokenJkt(accessToken), Thumbprint(proof));
                break;
        }

        Assert.Equal(fault == Fault.SampleApiReplayProof ? 2 : 1, requests.Count);
    }
}
