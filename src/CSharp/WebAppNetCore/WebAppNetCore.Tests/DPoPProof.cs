using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WebAppNetCore.OAuth;
using Xunit;

namespace WebAppNetCore.Tests;

/// <summary>
/// Reads and checks a DPoP proof as RFC 9449 section 4.3 describes, independently of the code that created it.
/// </summary>
internal sealed record DPoPProof(JsonWebToken Token, JsonElement Header, JsonElement Payload, string Thumbprint)
{
    internal string Alg => Token.Alg;

    internal string Jti => Payload.GetProperty("jti").GetString()!;

    internal string? Claim(string name) => Payload.TryGetProperty(name, out var value) ? value.GetString() : null;

    internal static DPoPProof Read(string proof)
    {
        var token = new JsonWebToken(proof);
        var header = JsonDocument.Parse(Base64UrlEncoder.Decode(token.EncodedHeader)).RootElement.Clone();
        var payload = JsonDocument.Parse(Base64UrlEncoder.Decode(token.EncodedPayload)).RootElement.Clone();
        var jwk = header.GetProperty("jwk");
        var thumbprint = DPoPKey.ComputeThumbprint(jwk.GetProperty("n").GetString()!, jwk.GetProperty("e").GetString()!);
        return new DPoPProof(token, header, payload, thumbprint);
    }

    /// <summary>
    /// Checks the header, the signature with the embedded key, and the claims. Give the access token for a resource request.
    /// </summary>
    internal static async Task<DPoPProof> ValidateAsync(string? proof, string htm, string htu, string? accessToken = null)
    {
        Assert.False(string.IsNullOrEmpty(proof), "The request has no DPoP proof.");
        var result = Read(proof!);

        Assert.Equal("dpop+jwt", result.Header.GetProperty("typ").GetString());
        Assert.False(result.Header.TryGetProperty("kid", out _), "The proof header has a kid.");
        var jwk = result.Header.GetProperty("jwk");
        Assert.Equal(new[] { "e", "kty", "n" }, jwk.EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal));
        Assert.Equal("RSA", jwk.GetProperty("kty").GetString());

        var validation = await new JsonWebTokenHandler().ValidateTokenAsync(proof, new TokenValidationParameters
        {
            IssuerSigningKey = new JsonWebKey(jwk.GetRawText()),
            ValidTypes = new[] { "dpop+jwt" },
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            RequireExpirationTime = false
        });
        Assert.True(validation.IsValid, validation.Exception?.Message);

        Assert.Equal(htm, result.Claim("htm"));
        Assert.Equal(htu, result.Claim("htu"));
        Assert.False(string.IsNullOrEmpty(result.Jti));
        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(result.Payload.GetProperty("iat").GetInt64());
        Assert.InRange(issuedAt, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(1));
        Assert.False(result.Payload.TryGetProperty("exp", out _), "The proof has exp.");
        Assert.False(result.Payload.TryGetProperty("nbf", out _), "The proof has nbf.");
        Assert.Equal(accessToken == null ? null : AccessTokenHash(accessToken), result.Claim("ath"));
        return result;
    }

    internal static string AccessTokenHash(string accessToken)
    {
        return Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));
    }
}
