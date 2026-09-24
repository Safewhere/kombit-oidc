using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System.Net;
using System.Text.RegularExpressions;
using Xunit;

namespace WebAppNetCore.Tests;

public sealed class WebAppNetCoreIntegrationTests
{
    [Fact]
    public async Task AnonymousMvcAndStaticRoutesAreAvailable()
    {
        using var factory = new TestWebApplicationFactory();
        using var client = CreateClient(factory);

        using var homeResponse = await client.GetAsync("/");
        Assert.Equal(HttpStatusCode.OK, homeResponse.StatusCode);
        Assert.Contains("Home Page", await homeResponse.Content.ReadAsStringAsync());

        using var aboutResponse = await client.GetAsync("/Home/About");
        Assert.Equal(HttpStatusCode.OK, aboutResponse.StatusCode);
        Assert.Contains("application description page", await aboutResponse.Content.ReadAsStringAsync());

        using var staticResponse = await client.GetAsync("/css/site.css");
        Assert.Equal(HttpStatusCode.OK, staticResponse.StatusCode);
        Assert.Equal("text/css", staticResponse.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task InvalidLogoutRequestsAreRejectedWithoutProviderCalls()
    {
        using var factory = new TestWebApplicationFactory();
        using var client = CreateClient(factory);

        using var missingTokenResponse = await client.PostAsync(
            "/back-channel-logout",
            new StringContent(string.Empty));
        Assert.Equal(HttpStatusCode.BadRequest, missingTokenResponse.StatusCode);
        Assert.Contains("Logout token is required.", await missingTokenResponse.Content.ReadAsStringAsync());

        using var malformedTokenResponse = await client.PostAsync(
            "/back-channel-logout",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["logout_token"] = "not-a-jwt"
            }));
        Assert.Equal(HttpStatusCode.BadRequest, malformedTokenResponse.StatusCode);
        Assert.Contains("Invalid logout token format.", await malformedTokenResponse.Content.ReadAsStringAsync());

        using var invalidIssuerResponse = await client.GetAsync(
            "/front-channel-logout?iss=https%3A%2F%2Fevil.test&sid=unused");
        Assert.Equal(HttpStatusCode.OK, invalidIssuerResponse.StatusCode);
        Assert.Contains("Invalid issuer.", await invalidIssuerResponse.Content.ReadAsStringAsync());

        using var invalidSessionResponse = await client.GetAsync(
            "/front-channel-logout?iss=https%3A%2F%2Fprovider.test&sid=unused");
        Assert.Equal(HttpStatusCode.OK, invalidSessionResponse.StatusCode);
        Assert.Contains("Invalid session.", await invalidSessionResponse.Content.ReadAsStringAsync());

        using var signOutResponse = await client.GetAsync("/Account/SignOut");
        Assert.Equal(HttpStatusCode.Redirect, signOutResponse.StatusCode);
        var signOutLocation = signOutResponse.Headers.Location;
        Assert.NotNull(signOutLocation);
        Assert.Equal(
            "https://provider.test/logout",
            signOutLocation!.GetLeftPart(UriPartial.Path));
        var signOutParameters = QueryHelpers.ParseQuery(signOutLocation.Query);
        Assert.Equal(
            "http://localhost/Account/SignedOutCallback",
            signOutParameters["post_logout_redirect_uri"].ToString());
    }

    [Fact]
    public async Task SignInGetEmitsCustomAuthorizationParametersAndPkceWithoutPar()
    {
        using var factory = new TestWebApplicationFactory("GET");
        using var client = CreateClient(factory);

        var options = factory.Services
            .GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>()
            .Get(OpenIdConnectDefaults.AuthenticationScheme);
        Assert.Equal(PushedAuthorizationBehavior.Disable, options.PushedAuthorizationBehavior);

        using var response = await client.GetAsync(
            "/Account/SignIn?loa=loa-3&max_age=600&forceLogin=true");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location;
        Assert.NotNull(location);
        Assert.Equal(TestWebApplicationFactory.ProviderAuthorizationEndpoint, location!.GetLeftPart(UriPartial.Path));

        var parameters = QueryHelpers.ParseQuery(location.Query);
        Assert.Equal("code", parameters["response_type"].ToString());
        Assert.Equal("openid", parameters["scope"].ToString());
        Assert.Equal("integration-test-client", parameters["client_id"].ToString());
        Assert.Equal("loa-3", parameters["acr_values"].ToString());
        Assert.Equal("600", parameters["max_age"].ToString());
        Assert.Equal("login", parameters["prompt"].ToString());
        Assert.Equal("S256", parameters["code_challenge_method"].ToString());
        Assert.False(string.IsNullOrWhiteSpace(parameters["code_challenge"].ToString()));
        Assert.False(string.IsNullOrWhiteSpace(parameters["state"].ToString()));
        Assert.False(string.IsNullOrWhiteSpace(parameters["nonce"].ToString()));
        Assert.False(parameters.ContainsKey("request_uri"));
        Assert.DoesNotContain("/par", location.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SignInPostAuthorizationMethodEmitsPassiveFormPostWithCustomParametersAndPkce()
    {
        using var factory = new TestWebApplicationFactory("POST");
        using var client = CreateClient(factory);

        using var response = await client.GetAsync(
            "/Account/SignIn?loa=loa-2&max_age=900&isPassive=true");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains(TestWebApplicationFactory.ProviderAuthorizationEndpoint, body);
        Assert.Contains("method=\"post\"", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("/par", body, StringComparison.OrdinalIgnoreCase);

        Assert.Equal("loa-2", ReadFormValue(body, "acr_values"));
        Assert.Equal("900", ReadFormValue(body, "max_age"));
        Assert.Equal("none", ReadFormValue(body, "prompt"));
        Assert.Equal("S256", ReadFormValue(body, "code_challenge_method"));
        Assert.False(string.IsNullOrWhiteSpace(ReadFormValue(body, "code_challenge")));
        Assert.False(string.IsNullOrWhiteSpace(ReadFormValue(body, "state")));
        Assert.False(string.IsNullOrWhiteSpace(ReadFormValue(body, "nonce")));
    }

    private static HttpClient CreateClient(TestWebApplicationFactory factory)
    {
        return factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
    }

    private static string ReadFormValue(string html, string name)
    {
        var pattern = $"<input[^>]+name=[\\\"']{Regex.Escape(name)}[\\\"'][^>]*value=[\\\"'](?<value>[^\\\"']*)[\\\"']";
        var match = Regex.Match(html, pattern, RegexOptions.IgnoreCase | RegexOptions.Singleline);
        Assert.True(match.Success, $"Form field '{name}' was not found.");
        return WebUtility.HtmlDecode(match.Groups["value"].Value);
    }
}
