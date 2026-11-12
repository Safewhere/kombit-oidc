using Xunit;

namespace WebAppNetCore.Tests;

/// <summary>
/// The sample takes every Identify URL from the discovery document, also the URLs of the post logout form and of
/// OpenID Connect Session Management, and only after the issuer check (US38478 AC-38478-06).
/// </summary>
public sealed class DiscoveredEndpointTests
{
    private const string OtherIssuer = "https://other.test/runtime/oauth2";

    private static Dictionary<string, string?> PostLogoutAndSessionManagement() => new()
    {
        ["OpenIdConnectOptions:EnablePostLogout"] = "true",
        ["OpenIdConnectOptions:EnableSessionManagement"] = "true"
    };

    [Fact]
    public async Task TheHomePageUsesTheEndSessionAndCheckSessionUrlsOfTheDiscoveryDocument()
    {
        using var factory = new TestWebApplicationFactory(settings: PostLogoutAndSessionManagement());
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);

        var page = await client.GetStringAsync("/");

        Assert.Contains($"<form action=\"{StubIdentify.EndSessionEndpoint}\"", page);
        Assert.Contains($"src='{StubIdentify.CheckSessionIframe}'", page);
    }

    [Fact]
    public async Task TheSessionCheckFrameUsesTheAuthorizationEndpointAndTheOriginOfTheDiscoveryDocument()
    {
        using var factory = new TestWebApplicationFactory(settings: PostLogoutAndSessionManagement());
        using var client = SignInFlow.CreateHttpsClient(factory);

        var frame = await client.GetStringAsync("/Account/RPIFrame");

        Assert.Contains($"var opDomain = \"{StubIdentify.Domain}\";", frame);
        Assert.Contains($"window.location= \"{StubIdentify.AuthorizationEndpoint}?response_type=code&", frame);
        Assert.Empty(factory.Identify.Requests);
    }

    [Fact]
    public async Task TheSessionCheckFrameRejectsADiscoveryDocumentOfAnotherIssuer()
    {
        var settings = PostLogoutAndSessionManagement();
        settings["OpenIdConnectOptions:ClaimsIssuer"] = OtherIssuer;
        using var factory = new TestWebApplicationFactory(settings: settings);
        using var client = SignInFlow.CreateHttpsClient(factory);

        var frame = await client.GetStringAsync("/Account/RPIFrame");

        Assert.Equal(
            $"The session check is not available: The issuer '{StubIdentify.Issuer}' in the discovery document differs from the configured issuer '{OtherIssuer}'.",
            frame);
    }
}
