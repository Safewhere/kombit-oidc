using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace SampleApi.Tests;

/// <summary>
/// Builds DPoP proofs by hand, so that a test can change each header and claim (RFC 9449 section 4.2).
/// </summary>
internal sealed class DPoPProofBuilder
{
    private readonly RSA key;

    internal DPoPProofBuilder(RSA key, string method, string path, string? accessToken)
    {
        this.key = key;
        var parameters = key.ExportParameters(false);
        Jwk = new Dictionary<string, object?>
        {
            ["kty"] = "RSA",
            ["n"] = Base64UrlEncoder.Encode(parameters.Modulus),
            ["e"] = Base64UrlEncoder.Encode(parameters.Exponent)
        };
        Header = new Dictionary<string, object?> { ["typ"] = "dpop+jwt", ["alg"] = "PS256", ["jwk"] = Jwk };
        Payload = new Dictionary<string, object?>
        {
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["htm"] = method,
            ["htu"] = SampleApiFactory.PublicBaseUrl + path,
            ["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };
        if (accessToken is not null)
        {
            Payload["ath"] = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));
        }
    }

    internal Dictionary<string, object?> Header { get; }

    internal Dictionary<string, object?> Jwk { get; }

    internal Dictionary<string, object?> Payload { get; }

    /// <summary>Signs with another key than the key in the jwk header.</summary>
    internal RSA? SigningKey { get; set; }

    internal static string Thumbprint(RSA key)
    {
        var parameters = key.ExportParameters(false);
        var jwk = new JsonWebKey { Kty = "RSA", N = Base64UrlEncoder.Encode(parameters.Modulus), E = Base64UrlEncoder.Encode(parameters.Exponent) };
        return Base64UrlEncoder.Encode(jwk.ComputeJwkThumbprint());
    }

    internal string Build()
    {
        var signingInput = Encode(Header) + "." + Encode(Payload);
        var signature = (SigningKey ?? key).SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        return signingInput + "." + Base64UrlEncoder.Encode(signature);
    }

    private static string Encode(Dictionary<string, object?> value) => Base64UrlEncoder.Encode(JsonSerializer.SerializeToUtf8Bytes(value));
}
