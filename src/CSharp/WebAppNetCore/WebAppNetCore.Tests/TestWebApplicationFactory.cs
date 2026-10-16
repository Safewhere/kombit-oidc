using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Collections.Generic;
using System.Net;
using System.Net.Http.Json;
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

    /// <summary>Whether the discovery document has pushed_authorization_request_endpoint.</summary>
    internal bool PublishParEndpoint { get; init; } = true;

    /// <summary>Whether the discovery document has authorization_response_iss_parameter_supported=true (RFC 9207).</summary>
    internal bool AdvertiseIssuerParameter { get; init; }

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

            // Only the values above. The appsettings.json of a developer, user secrets, and environment variables must not
            // change a test result. A building-block setting that a test does not set uses its default, which is the value
            // of the committed appsettings.json.
            configuration.Sources.Clear();
            configuration.AddInMemoryCollection(values);
        });

        builder.ConfigureTestServices(services =>
        {
            services.Configure<OpenIdConnectOptions>(
                OpenIdConnectDefaults.AuthenticationScheme,
                options =>
                {
                    options.Configuration = CreateProviderConfiguration();
                    // The sample sends PAR, token, and UserInfo requests itself. The handler must not call Identify.
                    options.BackchannelHttpHandler = new RejectingHttpMessageHandler();
                });
            services.AddHttpClient(IdentifyHttpClient.Name)
                .ConfigurePrimaryHttpMessageHandler(() => Identify);
            services.AddSingleton<IStartupFilter, TestSessionEndpointStartupFilter>();
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
              "introspection_endpoint": "{{StubIdentify.IntrospectionEndpoint}}",
              "revocation_endpoint": "{{StubIdentify.RevocationEndpoint}}",
              "jwks_uri": "{{ProviderIssuer}}/certs.idp"
            }
            """);
        if (PublishParEndpoint)
        {
            configuration.PushedAuthorizationRequestEndpoint = StubIdentify.ParEndpoint;
        }

        configuration.AuthorizationResponseIssParameterSupported = AdvertiseIssuerParameter;

        configuration.SigningKeys.Add(Identify.SigningKey);
        return configuration;
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

    /// <summary>
    /// Adds /test/session, which returns the claims, tokens, and items of the cookie session as JSON.
    /// </summary>
    private sealed class TestSessionEndpointStartupFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
        {
            return app =>
            {
                app.Map(TestSession.Path, branch => branch.Run(async context =>
                {
                    var result = await context.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    var session = new TestSession(
                        result.Principal?.Claims.Select(c => new TestClaim(c.Type, c.Value)).ToList() ?? new List<TestClaim>(),
                        result.Properties?.GetTokens().ToDictionary(t => t.Name, t => t.Value) ?? new Dictionary<string, string>(),
                        result.Properties?.Items.ToDictionary(i => i.Key, i => i.Value) ?? new Dictionary<string, string?>());
                    await context.Response.WriteAsJsonAsync(session);
                }));
                next(app);
            };
        }
    }
}

internal sealed record TestClaim(string Type, string Value);

internal sealed record TestSession(List<TestClaim> Claims, Dictionary<string, string> Tokens, Dictionary<string, string?> Items)
{
    internal const string Path = "/test/session";

    internal string? Claim(string type) => Claims.FirstOrDefault(c => c.Type == type)?.Value;

    internal static async Task<TestSession> GetAsync(HttpClient client)
    {
        return (await client.GetFromJsonAsync<TestSession>(Path))!;
    }
}
