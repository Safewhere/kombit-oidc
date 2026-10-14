using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using System.Net;
using System.Text.RegularExpressions;
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

    internal static async Task<AuthorizationRequest> StartAsync(
        HttpClient client,
        TestWebApplicationFactory factory,
        IDictionary<string, string>? fields = null)
    {
        using var response = await PostSignInAsync(client, fields);
        if (response.Headers.Location?.OriginalString == "/Home/Error")
        {
            Assert.Fail("The sign-in went to the error page: " + await ReadErrorMessageAsync(client));
        }

        return ReadAuthorizationRequest(response, factory);
    }

    /// <summary>Posts the sign-in form of the home page, with its antiforgery token.</summary>
    internal static async Task<HttpResponseMessage> PostSignInAsync(HttpClient client, IDictionary<string, string>? fields = null)
    {
        var page = await client.GetStringAsync("/");
        var form = new Dictionary<string, string>(fields ?? new Dictionary<string, string>())
        {
            ["__RequestVerificationToken"] = ReadFormValue(page, "__RequestVerificationToken")
        };
        return await client.PostAsync("/Account/SignIn", new FormUrlEncodedContent(form));
    }

    internal static string ReadFormValue(string html, string name)
    {
        var pattern = $"<input[^>]+name=[\\\"']{Regex.Escape(name)}[\\\"'][^>]*value=[\\\"'](?<value>[^\\\"']*)[\\\"']";
        var match = Regex.Match(html, pattern, RegexOptions.IgnoreCase | RegexOptions.Singleline);
        Assert.True(match.Success, $"Form field '{name}' was not found.");
        return WebUtility.HtmlDecode(match.Groups["value"].Value);
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
        string? iss = StubIdentify.Issuer,
        string code = Code)
    {
        factory.Identify.Nonce = request.Parameters.GetValueOrDefault("nonce");
        factory.Identify.RegisterCode(code, request.Parameters.GetValueOrDefault("nonce"));
        var query = new Dictionary<string, string?>
        {
            ["code"] = code,
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
        await AssertSignedInAsync(client, callback);
        return request;
    }

    internal static async Task AssertSignedInAsync(HttpClient client, HttpResponseMessage callback)
    {
        var location = callback.Headers.Location?.OriginalString;
        if (callback.StatusCode == HttpStatusCode.Redirect && location == "/")
        {
            return;
        }

        var detail = location == "/Home/Error" ? await ReadErrorMessageAsync(client) : await callback.Content.ReadAsStringAsync();
        Assert.Fail($"Expected a redirect to the home page, but got {(int)callback.StatusCode} to '{location}': {detail}");
    }

    /// <summary>Reads the message that the error page shows. The message is in TempData, so the page shows it once.</summary>
    internal static async Task<string> ReadErrorMessageAsync(HttpClient client)
    {
        return ErrorMessage(await client.GetStringAsync("/Home/Error"));
    }

    internal static string ErrorMessage(string errorPage)
    {
        var message = Regex.Match(errorPage, "<h3>Error Message</h3>\\s*<p>(?<message>.*?)</p>", RegexOptions.Singleline);
        return WebUtility.HtmlDecode(message.Groups["message"].Value.Trim());
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
