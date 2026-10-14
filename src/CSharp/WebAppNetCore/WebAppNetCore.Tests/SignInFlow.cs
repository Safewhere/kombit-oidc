using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using System.Net;
using Xunit;

namespace WebAppNetCore.Tests;

/// <summary>
/// Drives a browser sign-in against the sample and the stub Identify: the sign-in request, the authorization request
/// (direct or pushed), and the authorization response to the callback.
/// </summary>
internal static class SignInFlow
{
    internal const string Code = "code-1";

    /// <summary>The handler's correlation and nonce cookies are Secure, so end-to-end tests use an https base address.</summary>
    internal static HttpClient CreateHttpsClient(TestWebApplicationFactory factory)
    {
        return factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = new Uri("https://localhost")
        });
    }

    internal static async Task<AuthorizationRequest> StartAsync(HttpClient client, TestWebApplicationFactory factory, string query = "")
    {
        using var response = await client.GetAsync("/Account/SignIn" + query);
        return ReadAuthorizationRequest(response, factory);
    }

    internal static AuthorizationRequest ReadAuthorizationRequest(HttpResponseMessage response, TestWebApplicationFactory factory)
    {
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location!;
        Assert.Equal(StubIdentify.AuthorizationEndpoint, location.GetLeftPart(UriPartial.Path));

        var browserParameters = QueryHelpers.ParseQuery(location.Query)
            .ToDictionary(pair => pair.Key, pair => pair.Value.ToString(), StringComparer.Ordinal);
        var parameters = browserParameters.ContainsKey("request_uri")
            ? factory.Identify.RequestsTo(StubIdentify.ParEndpoint).Last().Form
            : browserParameters;
        return new AuthorizationRequest(location, browserParameters, parameters);
    }

    internal static Task<HttpResponseMessage> CompleteAsync(
        HttpClient client,
        TestWebApplicationFactory factory,
        AuthorizationRequest request,
        string? iss = StubIdentify.Issuer)
    {
        factory.Identify.Nonce = request.Parameters.GetValueOrDefault("nonce");
        var query = new Dictionary<string, string?>
        {
            ["code"] = Code,
            ["state"] = request.Parameters["state"]
        };
        if (iss != null)
        {
            query["iss"] = iss;
        }

        return client.GetAsync(QueryHelpers.AddQueryString("/signin-oidc", query));
    }

    /// <summary>Signs in and checks that the sample redirects to the home page.</summary>
    internal static async Task<AuthorizationRequest> SignInAsync(HttpClient client, TestWebApplicationFactory factory)
    {
        var request = await StartAsync(client, factory);
        using var callback = await CompleteAsync(client, factory, request);
        AssertSignedIn(callback);
        return request;
    }

    internal static void AssertSignedIn(HttpResponseMessage callback)
    {
        var location = callback.Headers.Location?.OriginalString;
        Assert.True(
            callback.StatusCode == HttpStatusCode.Redirect && location == "/",
            $"Expected a redirect to the home page, but got {(int)callback.StatusCode} to '{location}': "
                + callback.Content.ReadAsStringAsync().GetAwaiter().GetResult());
    }

    /// <summary>Checks that the sample redirects to the error page and returns the page.</summary>
    internal static async Task<string> AssertErrorPageAsync(HttpClient client, HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/Home/Error", response.Headers.Location!.OriginalString);
        return await client.GetStringAsync("/Home/Error");
    }
}

internal sealed record AuthorizationRequest(
    Uri Location,
    IReadOnlyDictionary<string, string> BrowserParameters,
    IReadOnlyDictionary<string, string> Parameters);
