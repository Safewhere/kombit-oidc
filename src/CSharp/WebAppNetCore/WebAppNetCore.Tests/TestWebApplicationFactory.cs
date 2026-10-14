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
using WebAppNetCore.OAuth;

namespace WebAppNetCore.Tests;

internal sealed class TestWebApplicationFactory : WebApplicationFactory<Program>
{
    internal const string ProviderAuthorizationEndpoint = StubIdentify.AuthorizationEndpoint;
    internal const string ProviderIssuer = StubIdentify.Issuer;
    internal const string ClientId = "integration-test-client";
    internal const string ClientSecret = "integration-test-secret";

    private readonly string authorizationEndpointMethod;
    private readonly IDictionary<string, string?> settings;

    internal TestWebApplicationFactory(string authorizationEndpointMethod = "GET", IDictionary<string, string?>? settings = null)
    {
        this.authorizationEndpointMethod = authorizationEndpointMethod;
        this.settings = settings ?? new Dictionary<string, string?>();
    }

    internal StubIdentify Identify { get; } = new(ClientId);

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
            var values = new Dictionary<string, string?>
            {
                ["OpenIdConnectOptions:ClientId"] = ClientId,
                ["OpenIdConnectOptions:ClientSecret"] = ClientSecret,
                ["OpenIdConnectOptions:ResponseType"] = "code",
                ["OpenIdConnectOptions:RequireNonce"] = "true",
                ["OpenIdConnectOptions:ResponseMode"] = "",
                ["OpenIdConnectOptions:AuthorizationEndpointMethod"] = authorizationEndpointMethod,
                ["OpenIdConnectOptions:ClaimsIssuer"] = ProviderIssuer,
                ["OpenIdConnectOptions:IssuerDomain"] = StubIdentify.Domain,
                ["OpenIdConnectOptions:Scope"] = "openid",
                ["OpenIdConnectOptions:EnableSessionManagement"] = "false",
                ["OpenIdConnectOptions:EnablePostLogout"] = "false",
                ["OpenIdConnectOptions:CheckSessionIframeUri"] = StubIdentify.Domain + "/runtime/openidconnect/sessionlogout.idp",
                ["OpenIdConnectOptions:TokenAuthnMethod"] = "client_secret_post"
            };
            foreach (var setting in settings)
            {
                values[setting.Key] = setting.Value;
            }

            configuration.AddInMemoryCollection(values);
        });

        builder.ConfigureTestServices(services =>
        {
            services.Configure<OpenIdConnectOptions>(
                OpenIdConnectDefaults.AuthenticationScheme,
                options =>
                {
                    options.Configuration = CreateProviderConfiguration();
                    options.BackchannelHttpHandler = Identify;
                });
            services.AddHttpClient(IdentifyHttpClient.Name)
                .ConfigurePrimaryHttpMessageHandler(() => Identify);
        });
    }

    private OpenIdConnectConfiguration CreateProviderConfiguration()
    {
        var configuration = OpenIdConnectConfiguration.Create($$"""
            {
              "issuer": "{{ProviderIssuer}}",
              "authorization_endpoint": "{{ProviderAuthorizationEndpoint}}",
              "token_endpoint": "{{StubIdentify.TokenEndpoint}}",
              "userinfo_endpoint": "{{StubIdentify.UserInfoEndpoint}}",
              "end_session_endpoint": "{{StubIdentify.EndSessionEndpoint}}",
              "jwks_uri": "{{ProviderIssuer}}/certs.idp",
              "pushed_authorization_request_endpoint": "{{StubIdentify.ParEndpoint}}"
            }
            """);
        configuration.SigningKeys.Add(Identify.SigningKey);
        return configuration;
    }
}
