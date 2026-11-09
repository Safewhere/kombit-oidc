using System.Collections.Concurrent;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication;

namespace SampleApi;

/// <summary>
/// The services and the two operations of the sample resource server (contract sections 5 and 6).
/// </summary>
public static class SampleApiEndpoints
{
    public const int MaximumNoteLength = 200;

    public static IServiceCollection AddSampleApi(this IServiceCollection services)
    {
        services.AddOptions<SampleApiOptions>()
            .BindConfiguration(SampleApiOptions.SectionName)
            .Validate(SampleApiOptions.IsValid, "SampleApi needs an https Issuer, an Audience, an absolute PublicBaseUrl, and a ClientId.")
            .ValidateOnStart();
        services.AddSingleton(TimeProvider.System);
        services.AddHttpClient(IdentifyMetadata.HttpClientName);
        services.AddSingleton<IdentifyMetadata>();
        services.AddSingleton<AccessTokenValidator>();
        services.AddSingleton<DPoPReplayStore>();
        services.AddSingleton<DPoPProofValidator>();
        services.AddSingleton(serviceProvider => ClientAssertionFactory.FromSettings(
            serviceProvider.GetRequiredService<Microsoft.Extensions.Options.IOptions<SampleApiOptions>>().Value,
            serviceProvider.GetRequiredService<TimeProvider>()));
        services.AddSingleton<IntrospectionClient>();
        services.AddSingleton<NoteStore>();
        services.AddAuthentication(DPoPAuthenticationHandler.SchemeName)
            .AddScheme<AuthenticationSchemeOptions, DPoPAuthenticationHandler>(DPoPAuthenticationHandler.SchemeName, null);
        services.AddAuthorization();
        return services;
    }

    public static WebApplication MapSampleApiEndpoints(this WebApplication app)
    {
        app.MapGet("/api/profile", (ClaimsPrincipal user) => Results.Ok(new ProfileResponse(
                user.FindFirstValue("sub")!,
                user.FindFirstValue("client_id"),
                string.Join(' ', user.FindAll("scope").Select(claim => claim.Value)),
                new BindingResponse("DPoP", user.FindFirstValue("jkt")!))))
            .RequireAuthorization()
            .AddEndpointFilter(new RequireScopeFilter(SampleApiScopes.Read));

        // The endpoint reads the JSON body itself. A body parameter would make routing reject a form body with HTTP 415 before the
        // authentication, and the access_token form parameter must get invalid_request (contract section 7).
        app.MapPost("/api/notes", async (HttpRequest request, ClaimsPrincipal user, NoteStore notes) =>
            {
                NoteRequest? body = null;
                if (request.HasJsonContentType())
                {
                    try
                    {
                        body = await request.ReadFromJsonAsync<NoteRequest>(request.HttpContext.RequestAborted);
                    }
                    catch (JsonException)
                    {
                        body = null;
                    }
                }

                if (body?.Text is null || body.Text.Length == 0 || body.Text.Length > MaximumNoteLength)
                {
                    return Results.BadRequest(new ErrorResponse("invalid_request", $"The note needs a JSON body with a text of 1 to {MaximumNoteLength} characters."));
                }

                var note = notes.Add(user.FindFirstValue("sub")!, body.Text);
                return Results.Created("/api/notes", note);
            })
            .RequireAuthorization()
            .AddEndpointFilter(new RequireScopeFilter(SampleApiScopes.Write));

        return app;
    }
}

/// <summary>
/// Step 6 of the contract: the scope of the access token must contain the scope of the operation. Otherwise HTTP 403 with
/// insufficient_scope (RFC 6750 section 3.1).
/// </summary>
public sealed class RequireScopeFilter : IEndpointFilter
{
    private readonly string scope;

    public RequireScopeFilter(string scope)
    {
        this.scope = scope;
    }

    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        if (!context.HttpContext.User.FindAll("scope").Any(claim => string.Equals(claim.Value, scope, StringComparison.Ordinal)))
        {
            context.HttpContext.Response.Headers.WWWAuthenticate = DPoPChallenge.Create("insufficient_scope", scope);
            return Results.Json(new ErrorResponse("insufficient_scope", "The access token does not have the scope of this operation."),
                statusCode: StatusCodes.Status403Forbidden);
        }

        return await next(context);
    }
}

/// <summary>The notes of each subject, in memory until the API stops.</summary>
public sealed class NoteStore
{
    private readonly ConcurrentDictionary<string, ConcurrentQueue<NoteResponse>> notes = new(StringComparer.Ordinal);
    private readonly TimeProvider timeProvider;

    public NoteStore(TimeProvider timeProvider)
    {
        this.timeProvider = timeProvider;
    }

    public NoteResponse Add(string subject, string text)
    {
        var note = new NoteResponse(text, timeProvider.GetUtcNow());
        notes.GetOrAdd(subject, _ => new ConcurrentQueue<NoteResponse>()).Enqueue(note);
        return note;
    }
}

public sealed record NoteRequest([property: JsonPropertyName("text")] string? Text);

public sealed record NoteResponse([property: JsonPropertyName("text")] string Text, [property: JsonPropertyName("created")] DateTimeOffset Created);

public sealed record BindingResponse([property: JsonPropertyName("type")] string Type, [property: JsonPropertyName("jkt")] string Jkt);

public sealed record ProfileResponse(
    [property: JsonPropertyName("sub")] string Subject,
    [property: JsonPropertyName("client_id")] string? ClientId,
    [property: JsonPropertyName("scope")] string Scope,
    [property: JsonPropertyName("binding")] BindingResponse Binding);
