using Microsoft.AspNetCore.WebUtilities;
using Xunit;

namespace WebAppNetCore.Tests;

public sealed class AuthorizationResponseIssuerTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AMatchingIssIsAccepted(bool advertised)
    {
        using var factory = new TestWebApplicationFactory { AdvertiseIssuerParameter = advertised };
        using var client = SignInFlow.CreateHttpsClient(factory);
        var request = await SignInFlow.StartAsync(client, factory);

        using var callback = await SignInFlow.CompleteAsync(client, factory, request, iss: StubIdentify.Issuer);

        await SignInFlow.AssertSignedInAsync(client, callback);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AnotherIssIsRejectedBeforeTheCodeIsRedeemed(bool advertised)
    {
        using var factory = new TestWebApplicationFactory { AdvertiseIssuerParameter = advertised };
        using var client = SignInFlow.CreateHttpsClient(factory);
        var request = await SignInFlow.StartAsync(client, factory);

        // A mix-up attack: the response comes from another authorization server.
        using var callback = await SignInFlow.CompleteAsync(client, factory, request, iss: "https://attacker.test/runtime/oauth2");

        var errorPage = await SignInFlow.AssertErrorPageAsync(client, callback);
        Assert.Equal(
            $"The iss parameter 'https://attacker.test/runtime/oauth2' of the authorization response is not the issuer '{StubIdentify.Issuer}' (RFC 9207).",
            SignInFlow.ErrorMessage(errorPage));
        Assert.Empty(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint));
    }

    [Fact]
    public async Task AMissingIssIsRejectedWhenDiscoveryAdvertisesIt()
    {
        using var factory = new TestWebApplicationFactory { AdvertiseIssuerParameter = true };
        using var client = SignInFlow.CreateHttpsClient(factory);
        var request = await SignInFlow.StartAsync(client, factory);

        using var callback = await SignInFlow.CompleteAsync(client, factory, request, iss: null);

        var errorPage = await SignInFlow.AssertErrorPageAsync(client, callback);
        Assert.Contains("has no iss parameter", SignInFlow.ErrorMessage(errorPage));
        Assert.Empty(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint));
    }

    [Fact]
    public async Task AMissingIssIsAcceptedWhenDiscoveryDoesNotAdvertiseIt()
    {
        using var factory = new TestWebApplicationFactory();
        using var client = SignInFlow.CreateHttpsClient(factory);
        var request = await SignInFlow.StartAsync(client, factory);

        using var callback = await SignInFlow.CompleteAsync(client, factory, request, iss: null);

        await SignInFlow.AssertSignedInAsync(client, callback);
    }

    [Fact]
    public async Task AnErrorResponseIsCheckedToo()
    {
        using var factory = new TestWebApplicationFactory { AdvertiseIssuerParameter = true };
        using var client = SignInFlow.CreateHttpsClient(factory);
        var request = await SignInFlow.StartAsync(client, factory);

        using var callback = await client.GetAsync(QueryHelpers.AddQueryString("/signin-oidc", new Dictionary<string, string?>
        {
            ["error"] = "invalid_request",
            ["state"] = request.Parameters["state"],
            ["iss"] = StubIdentify.Issuer
        }));

        // A matching iss lets the handler report the Identify error.
        var errorPage = await SignInFlow.AssertErrorPageAsync(client, callback);
        Assert.Contains("invalid_request", SignInFlow.ErrorMessage(errorPage));
    }
}
