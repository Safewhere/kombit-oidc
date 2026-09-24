using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Collections.Generic;
using System.Net;

namespace WebAppNetCore.Tests;

internal sealed class TestWebApplicationFactory : WebApplicationFactory<Program>
{
    internal const string ProviderAuthorizationEndpoint = "https://provider.test/authorize";
    internal const string ProviderIssuer = "https://provider.test";

    private readonly string authorizationEndpointMethod;

    internal TestWebApplicationFactory(string authorizationEndpointMethod = "GET")
    {
        this.authorizationEndpointMethod = authorizationEndpointMethod;
    }

    protected override IWebHostBuilder CreateWebHostBuilder()
    {
        return WebHost.CreateDefaultBuilder(Array.Empty<string>())
            .UseStartup<Startup>();
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.ConfigureAppConfiguration((_, configuration) =>
        {
            configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["OpenIdConnectOptions:ClientId"] = "integration-test-client",
                ["OpenIdConnectOptions:ClientSecret"] = "integration-test-secret",
                ["OpenIdConnectOptions:ResponseType"] = "code",
                ["OpenIdConnectOptions:RequireNonce"] = "true",
                ["OpenIdConnectOptions:ResponseMode"] = "",
                ["OpenIdConnectOptions:AuthorizationEndpointMethod"] = authorizationEndpointMethod,
                ["OpenIdConnectOptions:ClaimsIssuer"] = ProviderIssuer,
                ["OpenIdConnectOptions:IssuerDomain"] = ProviderIssuer,
                ["OpenIdConnectOptions:Scope"] = "openid",
                ["OpenIdConnectOptions:EnableSessionManagement"] = "false",
                ["OpenIdConnectOptions:EnablePostLogout"] = "false",
                ["OpenIdConnectOptions:CheckSessionIframeUri"] = "https://provider.test/session",
                ["OpenIdConnectOptions:TokenAuthnMethod"] = "client_secret_post"
            });
        });

        builder.ConfigureTestServices(services =>
        {
            services.Configure<OpenIdConnectOptions>(
                OpenIdConnectDefaults.AuthenticationScheme,
                options =>
                {
                    options.Configuration = CreateProviderConfiguration();
                    options.BackchannelHttpHandler = new RejectingHttpMessageHandler();
                });
        });
    }

    private static OpenIdConnectConfiguration CreateProviderConfiguration()
    {
        return OpenIdConnectConfiguration.Create($$"""
            {
              "issuer": "{{ProviderIssuer}}",
              "authorization_endpoint": "{{ProviderAuthorizationEndpoint}}",
              "token_endpoint": "{{ProviderIssuer}}/token",
              "userinfo_endpoint": "{{ProviderIssuer}}/userinfo",
              "end_session_endpoint": "{{ProviderIssuer}}/logout",
              "jwks_uri": "{{ProviderIssuer}}/jwks",
              "pushed_authorization_request_endpoint": "{{ProviderIssuer}}/par"
            }
            """);
    }

    private sealed class RejectingHttpMessageHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            throw new InvalidOperationException(
                $"Unexpected OIDC backchannel request: {request.Method} {request.RequestUri}");
        }
    }
}
