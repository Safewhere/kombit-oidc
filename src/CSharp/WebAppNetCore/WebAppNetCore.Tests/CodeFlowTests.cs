using Microsoft.AspNetCore.WebUtilities;
using System.Net;
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

    internal static string CodeChallenge(string codeVerifier)
    {
        return WebEncoders.Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)));
    }
}
