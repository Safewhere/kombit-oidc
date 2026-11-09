using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace SampleApi;

/// <summary>
/// Runs the checks of contract section 6, steps 1 to 5, for each request. Step 6 (the scope) is <see cref="RequireScopeFilter"/>.
/// </summary>
public sealed class DPoPAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public const string SchemeName = "DPoP";
    private const string FailureItemKey = "SampleApi.Failure";

    private readonly AccessTokenValidator accessTokenValidator;
    private readonly DPoPProofValidator proofValidator;
    private readonly IntrospectionClient introspectionClient;
    private readonly SampleApiOptions sampleApiOptions;

    public DPoPAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder,
        AccessTokenValidator accessTokenValidator, DPoPProofValidator proofValidator, IntrospectionClient introspectionClient,
        IOptions<SampleApiOptions> sampleApiOptions)
        : base(options, logger, encoder)
    {
        this.accessTokenValidator = accessTokenValidator;
        this.proofValidator = proofValidator;
        this.introspectionClient = introspectionClient;
        this.sampleApiOptions = sampleApiOptions.Value;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        try
        {
            var accessToken = await ReadAccessTokenAsync();
            if (accessToken is null)
            {
                return AuthenticateResult.NoResult();
            }

            var proofs = Request.Headers["DPoP"];
            if (proofs.Count == 0)
            {
                throw ProtectedResourceException.InvalidProof("The request has no DPoP proof.");
            }

            if (proofs.Count > 1)
            {
                throw ProtectedResourceException.InvalidRequest("The request has more than one DPoP header.");
            }

            var token = await accessTokenValidator.ValidateAsync(accessToken, Context.RequestAborted);
            await proofValidator.ValidateAsync(proofs[0]!, Request.Method, CreateRequestUri(), token);
            var introspection = await introspectionClient.IntrospectAsync(accessToken, Context.RequestAborted);
            if (!introspection.Active)
            {
                throw ProtectedResourceException.InvalidToken("Introspection reports that the access token is not active, for example because it was revoked.");
            }

            if (!string.Equals(introspection.TokenType, "DPoP", StringComparison.Ordinal) || !string.Equals(introspection.Jkt, token.Jkt, StringComparison.Ordinal))
            {
                throw ProtectedResourceException.InvalidToken("The token_type or cnf.jkt of the introspection result does not match the access token.");
            }

            var identity = new ClaimsIdentity(SchemeName);
            identity.AddClaim(new Claim("sub", token.Subject));
            identity.AddClaim(new Claim("jkt", token.Jkt));
            if (!string.IsNullOrEmpty(introspection.ClientId))
            {
                identity.AddClaim(new Claim("client_id", introspection.ClientId));
            }

            foreach (var scope in token.Scopes)
            {
                identity.AddClaim(new Claim("scope", scope));
            }

            return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName));
        }
        catch (ProtectedResourceException exception)
        {
            // The reason never contains a token, a proof, or an assertion.
            Logger.LogWarning("The request {Method} {Path} was rejected with HTTP {Status}: {Reason}",
                Request.Method, Request.Path, exception.StatusCode, exception.Reason);
            Context.Items[FailureItemKey] = exception;
            return AuthenticateResult.Fail(exception.Message);
        }
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        var failure = Context.Items[FailureItemKey] as ProtectedResourceException;
        Response.StatusCode = failure?.StatusCode ?? StatusCodes.Status401Unauthorized;
        if (Response.StatusCode != StatusCodes.Status503ServiceUnavailable)
        {
            Response.Headers.WWWAuthenticate = DPoPChallenge.Create(failure?.Error);
        }

        if (failure is not null)
        {
            await Response.WriteAsJsonAsync(new ErrorResponse(failure.Error ?? "temporarily_unavailable", failure.Message));
        }
    }

    /// <summary>
    /// Step 1: the access token comes only in the Authorization header with the DPoP scheme. Returns null when the request has no
    /// Authorization header and no access token parameter.
    /// </summary>
    private async Task<string?> ReadAccessTokenAsync()
    {
        if (Request.Query.ContainsKey("access_token"))
        {
            throw ProtectedResourceException.InvalidRequest("The request has an access_token query parameter (FAPI 2.0 section 5.3.4 item 2).");
        }

        if (Request.HasFormContentType && (await Request.ReadFormAsync(Context.RequestAborted)).ContainsKey("access_token"))
        {
            throw ProtectedResourceException.InvalidRequest("The request has an access_token form parameter.");
        }

        var authorization = Request.Headers.Authorization;
        if (authorization.Count == 0)
        {
            return null;
        }

        if (authorization.Count > 1)
        {
            throw ProtectedResourceException.InvalidRequest("The request has more than one Authorization header.");
        }

        var value = authorization[0] ?? string.Empty;
        var separator = value.IndexOf(' ');
        var scheme = separator < 0 ? value : value[..separator];
        if (!string.Equals(scheme, SchemeName, StringComparison.OrdinalIgnoreCase))
        {
            throw ProtectedResourceException.InvalidToken("The Authorization header does not use the DPoP scheme.");
        }

        var accessToken = separator < 0 ? string.Empty : value[(separator + 1)..].Trim();
        if (accessToken.Length == 0)
        {
            throw ProtectedResourceException.InvalidToken("The Authorization header has no access token.");
        }

        return accessToken;
    }

    /// <summary>The URL that htu must name: the configured public base URL and the path, never the Host or forwarding headers.</summary>
    private Uri CreateRequestUri()
    {
        return new Uri(sampleApiOptions.PublicBaseUrl.TrimEnd('/') + Request.PathBase + Request.Path);
    }
}

/// <summary>The JSON body of an error response.</summary>
public sealed record ErrorResponse(
    [property: System.Text.Json.Serialization.JsonPropertyName("error")] string Error,
    [property: System.Text.Json.Serialization.JsonPropertyName("error_description")] string Description);
