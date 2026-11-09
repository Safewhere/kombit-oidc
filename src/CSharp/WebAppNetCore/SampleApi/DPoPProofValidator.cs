using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace SampleApi;

/// <summary>
/// Checks the DPoP proof of a request to the API (RFC 9449 section 4.3 and section 7.1; contract section 6 step 4).
/// </summary>
public sealed class DPoPProofValidator
{
    public static readonly TimeSpan MaximumAge = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan MaximumClockSkew = TimeSpan.FromSeconds(10);
    private const int MinimumKeySizeInBits = 2048;
    private static readonly string[] PrivateKeyMembers = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

    private readonly JsonWebTokenHandler handler = new() { MapInboundClaims = false };
    private readonly DPoPReplayStore replayStore;
    private readonly TimeProvider timeProvider;

    public DPoPProofValidator(DPoPReplayStore replayStore, TimeProvider timeProvider)
    {
        this.replayStore = replayStore;
        this.timeProvider = timeProvider;
    }

    public async Task ValidateAsync(string proof, string method, Uri requestUri, ValidatedAccessToken accessToken)
    {
        JsonWebToken token;
        try
        {
            token = new JsonWebToken(proof);
        }
        catch (ArgumentException)
        {
            throw ProtectedResourceException.InvalidProof("The DPoP proof is not a JWT.");
        }

        if (!string.Equals(token.Typ, "dpop+jwt", StringComparison.Ordinal))
        {
            throw ProtectedResourceException.InvalidProof("The typ of the DPoP proof is not dpop+jwt.");
        }

        if (!string.Equals(token.Alg, SecurityAlgorithms.RsaSsaPssSha256, StringComparison.Ordinal))
        {
            throw ProtectedResourceException.InvalidProof("The alg of the DPoP proof is not PS256.");
        }

        var key = ReadPublicKey(token);
        var signature = await handler.ValidateTokenAsync(token, new TokenValidationParameters
        {
            IssuerSigningKey = key,
            ValidAlgorithms = [SecurityAlgorithms.RsaSsaPssSha256],
            ValidTypes = ["dpop+jwt"],
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            RequireExpirationTime = false,
            RequireSignedTokens = true
        });
        if (!signature.IsValid)
        {
            throw ProtectedResourceException.InvalidProof("The signature of the DPoP proof is not valid.");
        }

        if (!token.TryGetPayloadValue<string>("htm", out var htm) || !string.Equals(htm, method, StringComparison.Ordinal))
        {
            throw ProtectedResourceException.InvalidProof("The htm of the DPoP proof is not the method of the request.");
        }

        if (!token.TryGetPayloadValue<string>("htu", out var htu) || !Uri.TryCreate(htu, UriKind.Absolute, out var htuUri)
            || Uri.Compare(htuUri, requestUri, UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.UriEscaped, StringComparison.Ordinal) != 0)
        {
            throw ProtectedResourceException.InvalidProof("The htu of the DPoP proof is not the URL of the request.");
        }

        if (!token.TryGetPayloadValue<long>("iat", out var iat))
        {
            throw ProtectedResourceException.InvalidProof("The DPoP proof has no numeric iat.");
        }

        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(iat);
        var now = timeProvider.GetUtcNow();
        if (issuedAt < now - MaximumAge || issuedAt > now + MaximumClockSkew)
        {
            throw ProtectedResourceException.InvalidProof("The iat of the DPoP proof is outside the accepted time window.");
        }

        if (!token.TryGetPayloadValue<string>("jti", out var jti) || string.IsNullOrEmpty(jti) || jti.Length > 256)
        {
            throw ProtectedResourceException.InvalidProof("The DPoP proof has no valid jti.");
        }

        if (!token.TryGetPayloadValue<string>("ath", out var ath) || !string.Equals(ath, ComputeAccessTokenHash(accessToken.RawToken), StringComparison.Ordinal))
        {
            throw ProtectedResourceException.InvalidProof("The ath of the DPoP proof is not the hash of the access token.");
        }

        var thumbprint = Base64UrlEncoder.Encode(key.ComputeJwkThumbprint());
        if (!string.Equals(thumbprint, accessToken.Jkt, StringComparison.Ordinal))
        {
            throw ProtectedResourceException.InvalidProof("The key of the DPoP proof is not the key that the access token is bound to.");
        }

        if (!replayStore.TryAdd(thumbprint, jti, issuedAt + MaximumAge + MaximumClockSkew))
        {
            throw ProtectedResourceException.InvalidProof("The DPoP proof was used before.");
        }
    }

    public static string ComputeAccessTokenHash(string accessToken)
    {
        return Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));
    }

    private static JsonWebKey ReadPublicKey(JsonWebToken token)
    {
        using var header = JsonDocument.Parse(Base64UrlEncoder.Decode(token.EncodedHeader));
        if (header.RootElement.TryGetProperty("crit", out _))
        {
            throw ProtectedResourceException.InvalidProof("The DPoP proof has a crit header, and this API supports no JWS extension.");
        }

        if (!header.RootElement.TryGetProperty("jwk", out var jwk) || jwk.ValueKind != JsonValueKind.Object)
        {
            throw ProtectedResourceException.InvalidProof("The DPoP proof has no jwk header.");
        }

        if (PrivateKeyMembers.Any(member => jwk.TryGetProperty(member, out _)))
        {
            throw ProtectedResourceException.InvalidProof("The jwk header of the DPoP proof contains a private key member.");
        }

        JsonWebKey key;
        try
        {
            key = new JsonWebKey(jwk.GetRawText());
        }
        catch (ArgumentException)
        {
            throw ProtectedResourceException.InvalidProof("The jwk header of the DPoP proof is not a JSON Web Key.");
        }

        if (!string.Equals(key.Kty, JsonWebAlgorithmsKeyTypes.RSA, StringComparison.Ordinal) || string.IsNullOrEmpty(key.N) || string.IsNullOrEmpty(key.E)
            || key.KeySize < MinimumKeySizeInBits)
        {
            throw ProtectedResourceException.InvalidProof("The jwk header of the DPoP proof is not a public RSA key of at least 2048 bits.");
        }

        return key;
    }
}

/// <summary>
/// The replay store of the API (contract section 8). It keeps each proof jti with the thumbprint of the proof key until the end of
/// the iat window. It is in memory, because the sample runs as one instance.
/// </summary>
public sealed class DPoPReplayStore
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> entries = new(StringComparer.Ordinal);
    private readonly TimeProvider timeProvider;

    public DPoPReplayStore(TimeProvider timeProvider)
    {
        this.timeProvider = timeProvider;
    }

    /// <summary>Returns false when the same key already used the jti.</summary>
    public bool TryAdd(string keyThumbprint, string jti, DateTimeOffset keepUntil)
    {
        var now = timeProvider.GetUtcNow();
        foreach (var expired in entries.Where(entry => entry.Value < now).Select(entry => entry.Key).ToList())
        {
            entries.TryRemove(expired, out _);
        }

        return entries.TryAdd(keyThumbprint + " " + jti, keepUntil);
    }
}
