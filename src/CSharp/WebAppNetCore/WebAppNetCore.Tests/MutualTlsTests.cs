using System.Net;
using WebAppNetCore.OAuth;
using Xunit;

namespace WebAppNetCore.Tests;

/// <summary>
/// Mutual TLS (RFC 8705): the TLS client certificate authenticates the client (tls_client_auth and self_signed_tls_client_auth),
/// or binds the access tokens with another method (MutualTls:UseEndpointAliases). The requests that authenticate the client go
/// to the mtls_endpoint_aliases of the discovery document. In the tests, the HttpClient for mutual TLS adds the header
/// StubIdentify.ClientCertificateHeader instead of the certificate, and the stub rejects a request at an alias without it.
/// </summary>
public sealed class MutualTlsTests : IDisposable
{
    private readonly TestCertificateFile certificate = new();

    public void Dispose() => certificate.Dispose();

    private Dictionary<string, string?> Settings(string method = "self_signed_tls_client_auth", bool faults = false)
    {
        var settings = new Dictionary<string, string?>(certificate.MutualTlsSettings(method))
        {
            ["OpenIdConnectOptions:PushedAuthorization"] = "Require"
        };
        if (faults)
        {
            settings["Testing:EnableFaultInjection"] = "true";
        }

        return settings;
    }

    private static Dictionary<string, string> WithFault(Fault fault) => new() { [FaultInjection.FieldName] = fault.ToString() };

    private static async Task<string> HomePageAsync(HttpClient client) => WebUtility.HtmlDecode(await client.GetStringAsync("/"));

    [Theory]
    [InlineData("tls_client_auth")]
    [InlineData("self_signed_tls_client_auth")]
    public async Task ASignInSendsThePushedRequestAndTheCodeToTheAliasesWithTheCertificateAndOnlyTheClientId(string method)
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(method));
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInFlow.SignInAsync(client, factory);

        var par = Assert.Single(factory.Identify.RequestsTo(StubIdentify.MtlsParEndpoint));
        var token = Assert.Single(factory.Identify.RequestsTo(StubIdentify.MtlsTokenEndpoint));
        foreach (var request in new[] { par, token })
        {
            Assert.Equal(certificate.Thumbprint, request.Header(StubIdentify.ClientCertificateHeader));
            Assert.Equal(TestWebApplicationFactory.ClientId, request.Form["client_id"]);
            Assert.False(request.Form.ContainsKey("client_secret"), "The request has a client secret.");
            Assert.False(request.Form.ContainsKey("client_assertion"), "The request has a client assertion.");
            Assert.Null(request.Header("Authorization"));
        }

        Assert.Equal("authorization_code", token.Form["grant_type"]);
        Assert.Empty(factory.Identify.RequestsTo(StubIdentify.ParEndpoint));
        Assert.Empty(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint));
    }

    [Fact]
    public async Task TheAccessTokenOfTheSessionIsBoundToTheCertificateAndUserInfoHasNoCertificate()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings());
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInFlow.SignInAsync(client, factory);

        var session = await TestSession.GetAsync(client);
        Assert.Equal(certificate.Thumbprint, AccessTokenInspector.ReadCertificateThumbprint(session.Tokens["access_token"]));
        // Identify has no mTLS alias for UserInfo.
        var userInfo = Assert.Single(factory.Identify.RequestsTo(StubIdentify.UserInfoEndpoint));
        Assert.Null(userInfo.Header(StubIdentify.ClientCertificateHeader));
    }

    [Fact]
    public async Task TheTraceShowsTheCertificateOfEachRequestAndTheBindingOfTheAccessToken()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings());
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInFlow.SignInAsync(client, factory);

        var page = await HomePageAsync(client);
        Assert.Contains("x5t#S256 " + certificate.Thumbprint, page);
        Assert.Contains("access token cnf.x5t#S256", page);
        Assert.Contains("Mutual TLS endpoint aliases (MutualTls)", page);
        Assert.Contains("True, certificate from file", page);
    }

    [Fact]
    public async Task ASignInFailsWhenTheAccessTokenIsNotBoundToTheCertificate()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings());
        factory.Identify.BindAccessTokensToCertificate = false;
        using var client = SignInFlow.CreateHttpsClient(factory);
        var request = await SignInFlow.StartAsync(client, factory);

        using var callback = await SignInFlow.CompleteAsync(client, factory, request);

        var page = await SignInFlow.AssertErrorPageAsync(client, callback);
        Assert.Contains("The access token is not bound to the client certificate (RFC 8705 section 3): its cnf.x5t#S256 is '(none)'", SignInFlow.ErrorMessage(page));
    }

    [Fact]
    public async Task ASignInFailsWithoutAnAliasAndSendsNothingToTheNormalEndpoint()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings()) { PublishMtlsEndpointAliases = false };
        using var client = SignInFlow.CreateHttpsClient(factory);

        using var response = await SignInFlow.PostSignInAsync(client);

        var page = await SignInFlow.AssertErrorPageAsync(client, response);
        Assert.Contains("The discovery document has no pushed_authorization_request_endpoint in mtls_endpoint_aliases", SignInFlow.ErrorMessage(page));
        Assert.Empty(factory.Identify.Requests);
    }

    [Fact]
    public async Task PrivateKeyJwtWithEndpointAliasesSendsTheAssertionWithTheCertificate()
    {
        var settings = new Dictionary<string, string?>(certificate.PrivateKeyJwtSettings())
        {
            ["OpenIdConnectOptions:PushedAuthorization"] = "Require",
            ["OpenIdConnectOptions:MutualTls:UseEndpointAliases"] = "true",
            ["OpenIdConnectOptions:MutualTls:CertificatePath"] = certificate.Path,
            ["OpenIdConnectOptions:MutualTls:CertificatePassword"] = TestCertificateFile.Password
        };
        using var factory = new TestWebApplicationFactory(settings: settings);
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInFlow.SignInAsync(client, factory);

        foreach (var request in new[] { Assert.Single(factory.Identify.RequestsTo(StubIdentify.MtlsParEndpoint)), Assert.Single(factory.Identify.RequestsTo(StubIdentify.MtlsTokenEndpoint)) })
        {
            Assert.Equal(certificate.Thumbprint, request.Header(StubIdentify.ClientCertificateHeader));
            await CodeFlowTests.ValidateClientAssertionAsync(request.Form["client_assertion"], certificate);
        }

        var session = await TestSession.GetAsync(client);
        Assert.Equal(certificate.Thumbprint, AccessTokenInspector.ReadCertificateThumbprint(session.Tokens["access_token"]));
    }

    [Fact]
    public async Task RefreshIntrospectionAndRevocationGoToTheAliasesWithTheCertificate()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings());
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);

        using (await SignInFlow.PostFormAsync(client, "/Account/Refresh"))
        using (await SignInFlow.PostFormAsync(client, "/Account/Introspect"))
        using (await SignInFlow.PostFormAsync(client, "/Account/Revoke"))
        {
        }

        var refresh = factory.Identify.RequestsTo(StubIdentify.MtlsTokenEndpoint).Last();
        Assert.Equal("refresh_token", refresh.Form["grant_type"]);
        var introspection = Assert.Single(factory.Identify.RequestsTo(StubIdentify.MtlsIntrospectionEndpoint));
        var revocation = Assert.Single(factory.Identify.RequestsTo(StubIdentify.MtlsRevocationEndpoint));
        foreach (var request in new[] { refresh, introspection, revocation })
        {
            Assert.Equal(certificate.Thumbprint, request.Header(StubIdentify.ClientCertificateHeader));
            Assert.Equal(TestWebApplicationFactory.ClientId, request.Form["client_id"]);
            Assert.False(request.Form.ContainsKey("client_secret"), "The request has a client secret.");
        }

        Assert.Empty(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint));
        Assert.Empty(factory.Identify.RequestsTo(StubIdentify.IntrospectionEndpoint));
        Assert.Empty(factory.Identify.RequestsTo(StubIdentify.RevocationEndpoint));
    }

    [Fact]
    public async Task MtlsParAtNormalEndpointSendsThePushedRequestToTheNormalEndpointWithoutTheCertificate()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(faults: true));
        using var client = SignInFlow.CreateHttpsClient(factory);

        await SignInFlow.StartAsync(client, factory, WithFault(Fault.MtlsParAtNormalEndpoint));

        var par = Assert.Single(factory.Identify.RequestsTo(StubIdentify.ParEndpoint));
        Assert.Null(par.Header(StubIdentify.ClientCertificateHeader));
        Assert.Equal(TestWebApplicationFactory.ClientId, par.Form["client_id"]);
        Assert.Empty(factory.Identify.RequestsTo(StubIdentify.MtlsParEndpoint));
    }

    [Fact]
    public async Task MtlsTokenAtNormalEndpointSendsTheCodeToTheNormalEndpointWithoutTheCertificate()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(faults: true));
        using var client = SignInFlow.CreateHttpsClient(factory);
        var request = await SignInFlow.StartAsync(client, factory, WithFault(Fault.MtlsTokenAtNormalEndpoint));

        using var callback = await SignInFlow.CompleteAsync(client, factory, request);

        var token = Assert.Single(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint));
        Assert.Null(token.Header(StubIdentify.ClientCertificateHeader));
        Assert.Empty(factory.Identify.RequestsTo(StubIdentify.MtlsTokenEndpoint));
        // The pushed request still went to the alias, with the certificate.
        Assert.Equal(certificate.Thumbprint, Assert.Single(factory.Identify.RequestsTo(StubIdentify.MtlsParEndpoint)).Header(StubIdentify.ClientCertificateHeader));
        // The stub, unlike Identify, accepts the request, and its access token has no certificate binding.
        var page = await SignInFlow.AssertErrorPageAsync(client, callback);
        Assert.Contains("The access token is not bound to the client certificate", SignInFlow.ErrorMessage(page));
    }

    [Fact]
    public async Task MtlsRefreshAtNormalEndpointSendsTheRefreshRequestToTheNormalEndpointWithoutTheCertificate()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(faults: true));
        using var client = SignInFlow.CreateHttpsClient(factory);
        await SignInFlow.SignInAsync(client, factory);
        factory.Identify.TokenResponder = _ => StubIdentify.OAuthError(HttpStatusCode.Unauthorized, "invalid_client",
            "The client must authenticate with its TLS client certificate at the mTLS endpoint alias (mtls_endpoint_aliases).");

        using (await SignInFlow.PostFormAsync(client, "/Account/Refresh", WithFault(Fault.MtlsRefreshAtNormalEndpoint)))
        {
        }

        var refresh = Assert.Single(factory.Identify.RequestsTo(StubIdentify.TokenEndpoint));
        Assert.Equal("refresh_token", refresh.Form["grant_type"]);
        Assert.Null(refresh.Header(StubIdentify.ClientCertificateHeader));
        Assert.Contains("The token endpoint returned HTTP 401: invalid_client", await HomePageAsync(client));
    }

    [Fact]
    public async Task ParWithoutClientAuthenticationSendsThePushedRequestToTheAliasWithoutTheCertificate()
    {
        using var factory = new TestWebApplicationFactory(settings: Settings(faults: true));
        using var client = SignInFlow.CreateHttpsClient(factory);

        using var response = await SignInFlow.PostSignInAsync(client, WithFault(Fault.ParWithoutClientAuthentication));

        var page = await SignInFlow.AssertErrorPageAsync(client, response);
        Assert.Contains("The PAR endpoint returned HTTP 403", SignInFlow.ErrorMessage(page));
        var par = Assert.Single(factory.Identify.RequestsTo(StubIdentify.MtlsParEndpoint));
        Assert.Null(par.Header(StubIdentify.ClientCertificateHeader));
    }

    [Fact]
    public async Task AMutualTlsFaultWithoutMutualTlsSendsNothing()
    {
        var settings = new Dictionary<string, string?>
        {
            ["OpenIdConnectOptions:PushedAuthorization"] = "Require",
            ["Testing:EnableFaultInjection"] = "true"
        };
        using var factory = new TestWebApplicationFactory(settings: settings);
        using var client = SignInFlow.CreateHttpsClient(factory);

        using var response = await SignInFlow.PostSignInAsync(client, WithFault(Fault.MtlsParAtNormalEndpoint));

        var page = await SignInFlow.AssertErrorPageAsync(client, response);
        Assert.Contains("The fault MtlsParAtNormalEndpoint needs mutual TLS", SignInFlow.ErrorMessage(page));
        Assert.Empty(factory.Identify.Requests);
    }

    [Theory]
    [InlineData("tls")]
    [InlineData("TLS_CLIENT_AUTH")]
    public void AnUnknownTokenAuthnMethodStopsTheApplication(string value)
    {
        using var factory = new TestWebApplicationFactory(settings: new Dictionary<string, string?> { ["OpenIdConnectOptions:TokenAuthnMethod"] = value });

        var exception = Assert.ThrowsAny<Exception>(() => factory.CreateClient());

        Assert.Contains($"'OpenIdConnectOptions:TokenAuthnMethod' has the invalid value '{value}'", exception.ToString());
    }

    [Fact]
    public void MutualTlsWithoutACertificateSettingStopsTheApplication()
    {
        using var factory = new TestWebApplicationFactory(settings: new Dictionary<string, string?> { ["OpenIdConnectOptions:TokenAuthnMethod"] = "tls_client_auth" });

        var exception = Assert.ThrowsAny<Exception>(() => factory.CreateClient());

        Assert.Contains("Mutual TLS needs exactly one of the settings 'OpenIdConnectOptions:MutualTls:CertificateThumbprint' and 'OpenIdConnectOptions:MutualTls:CertificatePath'", exception.ToString());
    }

    [Fact]
    public void MutualTlsWithBothCertificateSettingsStopsTheApplication()
    {
        var settings = Settings();
        settings["OpenIdConnectOptions:MutualTls:CertificateThumbprint"] = certificate.PublicCertificate.Thumbprint;
        using var factory = new TestWebApplicationFactory(settings: settings);

        var exception = Assert.ThrowsAny<Exception>(() => factory.CreateClient());

        Assert.Contains("Mutual TLS needs exactly one of the settings", exception.ToString());
    }

    [Fact]
    public void AThumbprintThatNoStoreHasStopsTheApplication()
    {
        var settings = new Dictionary<string, string?>
        {
            ["OpenIdConnectOptions:MutualTls:UseEndpointAliases"] = "true",
            ["OpenIdConnectOptions:MutualTls:CertificateThumbprint"] = new string('0', 40)
        };
        using var factory = new TestWebApplicationFactory(settings: settings);

        var exception = Assert.ThrowsAny<Exception>(() => factory.CreateClient());

        Assert.Contains("has no certificate with it", exception.ToString());
    }
}
