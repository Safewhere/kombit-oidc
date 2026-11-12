using Microsoft.IdentityModel.Tokens;
using System.Text.Json;
using Xunit;

namespace WebAppNetCore.Tests;

public sealed class ClientAssertionTests
{
    [Fact]
    public async Task TheIssuerAudienceIsTheDiscoveredIssuerAsOneJsonString()
    {
        using var certificate = new TestCertificateFile();
        var settings = certificate.PrivateKeyJwtSettings();
        settings["OpenIdConnectOptions:ClientAssertion:Audience"] = "Issuer";
        using var factory = new TestWebApplicationFactory(settings: settings);
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInFlow.SignInAsync(client, factory);

        var assertion = await CodeFlowTests.ValidateClientAssertionAsync(
            Assert.Single(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint)).Form["client_assertion"], certificate);
        using var payload = JsonDocument.Parse(Base64UrlEncoder.Decode(assertion.EncodedPayload));
        var audience = payload.RootElement.GetProperty("aud");
        Assert.Equal(JsonValueKind.String, audience.ValueKind);
        Assert.Equal(StubIdentify.Issuer, audience.GetString());
    }

    [Fact]
    public async Task TheSigningAlgorithmIsConfigurable()
    {
        using var certificate = new TestCertificateFile();
        var settings = certificate.PrivateKeyJwtSettings();
        settings["OpenIdConnectOptions:ClientAssertion:SigningAlgorithm"] = "PS256";
        using var factory = new TestWebApplicationFactory(settings: settings);
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInFlow.SignInAsync(client, factory);

        var assertion = await CodeFlowTests.ValidateClientAssertionAsync(
            Assert.Single(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint)).Form["client_assertion"], certificate);
        Assert.Equal(SecurityAlgorithms.RsaSsaPssSha256, assertion.Alg);
        Assert.Equal(Base64UrlEncoder.Encode(certificate.PublicCertificate.GetCertHash()), assertion.Kid);
        Assert.Equal(StubIdentify.TokenEndpoint, assertion.GetPayloadValue<string>("aud"));
    }

    [Theory]
    [InlineData("OpenIdConnectOptions:ClientAssertion:Audience", "PushedAuthorizationEndpoint")]
    [InlineData("OpenIdConnectOptions:ClientAssertion:SigningAlgorithm", "HS256")]
    public void AnInvalidValueStopsTheApplication(string key, string value)
    {
        using var factory = new TestWebApplicationFactory(settings: new Dictionary<string, string?> { [key] = value });

        var exception = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
        Assert.Contains($"'{key}' has the invalid value '{value}'", exception.ToString());
    }
}
