using System.Text.Json;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace SampleApi;

/// <summary>
/// An access token that passed steps 2 and 3 of the contract.
/// </summary>
public sealed record ValidatedAccessToken(string RawToken, string Subject, IReadOnlySet<string> Scopes, string Jkt);

/// <summary>
/// Validates the access token as a JWT (contract section 6 steps 2 and 3).
/// </summary>
public sealed class AccessTokenValidator
{
    private readonly JsonWebTokenHandler handler = new() { MapInboundClaims = false };
    private readonly IdentifyMetadata metadata;
    private readonly SampleApiOptions options;

    public AccessTokenValidator(IdentifyMetadata metadata, IOptions<SampleApiOptions> options)
    {
        this.metadata = metadata;
        this.options = options.Value;
    }

    public async Task<ValidatedAccessToken> ValidateAsync(string accessToken, CancellationToken cancellationToken)
    {
        var configuration = await metadata.GetAsync(cancellationToken);
        var result = await handler.ValidateTokenAsync(accessToken, CreateParameters(configuration));
        if (!result.IsValid && result.Exception is SecurityTokenSignatureKeyNotFoundException)
        {
            metadata.RequestRefresh();
            configuration = await metadata.GetAsync(cancellationToken);
            result = await handler.ValidateTokenAsync(accessToken, CreateParameters(configuration));
        }

        if (!result.IsValid)
        {
            throw ProtectedResourceException.InvalidToken("The JWT validation failed: " + result.Exception?.GetType().Name);
        }

        var token = (JsonWebToken)result.SecurityToken;
        var jkt = ReadDPoPThumbprint(token);
        var scopes = token.Claims
            .Where(claim => claim.Type == "scope")
            .SelectMany(claim => claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .ToHashSet(StringComparer.Ordinal);
        if (string.IsNullOrEmpty(token.Subject))
        {
            throw ProtectedResourceException.InvalidToken("The access token has no sub claim.");
        }

        return new ValidatedAccessToken(accessToken, token.Subject, scopes, jkt);
    }

    private TokenValidationParameters CreateParameters(OpenIdConnectConfiguration configuration)
    {
        return new TokenValidationParameters
        {
            ValidIssuer = options.NormalizedIssuer,
            ValidAudience = options.Audience,
            IssuerSigningKeys = configuration.SigningKeys,
            ValidAlgorithms = [SecurityAlgorithms.RsaSsaPssSha256],
            // RFC 9068 section 4: an ID token has typ JWT, so it fails here.
            ValidTypes = ["at+jwt"],
            ClockSkew = TimeSpan.FromSeconds(10),
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ValidateLifetime = true
        };
    }

    private static string ReadDPoPThumbprint(JsonWebToken token)
    {
        using var payload = JsonDocument.Parse(Base64UrlEncoder.Decode(token.EncodedPayload));
        if (!payload.RootElement.TryGetProperty("cnf", out var confirmation) || confirmation.ValueKind != JsonValueKind.Object)
        {
            throw ProtectedResourceException.InvalidToken("The access token has no cnf claim, so it is not sender-constrained.");
        }

        // A token that is also bound to a certificate needs the certificate check too (RFC 8705 section 3), which this API cannot do.
        if (confirmation.TryGetProperty("x5t#S256", out _))
        {
            throw ProtectedResourceException.InvalidToken("The access token is bound to a client certificate. This API accepts only DPoP-bound access tokens.");
        }

        if (confirmation.TryGetProperty("jkt", out var jkt) && jkt.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(jkt.GetString()))
        {
            return jkt.GetString()!;
        }

        throw ProtectedResourceException.InvalidToken("The cnf claim of the access token has no string jkt member.");
    }
}
