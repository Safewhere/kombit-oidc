using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace SampleApi.Tests;

/// <summary>
/// The parts of Identify that the API calls: the discovery document, the JWKS, and introspection. It also issues access tokens as
/// Identify does: PS256, typ at+jwt, the API audience, and cnf.jkt.
/// </summary>
internal sealed class StubIdentify : HttpMessageHandler
{
    internal const string Issuer = "https://identify.test/runtime/oauth2";
    internal const string DiscoveryUrl = Issuer + "/.well-known/openid-configuration";
    internal const string JwksUri = Issuer + "/certs.idp";
    internal const string IntrospectionEndpoint = Issuer + "/introspect.idp";
    internal const string Audience = "urn:kombit-oidc:sample-api";
    internal const string ClientId = "fapi-test-confidential";
    internal const string Subject = "fapi-test-user";
    internal const string AllScopes = "openid sample-api.read sample-api.write";

    private readonly RSA signingKey = RSA.Create(2048);
    private readonly RSA otherSigningKey = RSA.Create(2048);

    internal string DiscoveryIssuer { get; set; } = Issuer;

    internal ConcurrentQueue<Dictionary<string, string>> IntrospectionRequests { get; } = new();

    internal ConcurrentDictionary<string, bool> RevokedTokens { get; } = new(StringComparer.Ordinal);

    /// <summary>Replaces the default introspection response, which reads the claims of the token.</summary>
    internal Func<Dictionary<string, string>, HttpResponseMessage>? IntrospectionResponder { get; set; }

    internal string IssueAccessToken(string? jkt, string scope = AllScopes, string audience = Audience, string type = "at+jwt",
        DateTime? expires = null, Dictionary<string, object>? confirmation = null, bool signWithOtherKey = false, string issuer = Issuer)
    {
        var now = DateTime.UtcNow;
        var claims = new Dictionary<string, object> { ["sub"] = Subject, ["client_id"] = ClientId, ["scope"] = scope };
        var cnf = confirmation ?? (jkt is null ? null : new Dictionary<string, object> { ["jkt"] = jkt });
        if (cnf is not null)
        {
            claims["cnf"] = cnf;
        }

        var key = new RsaSecurityKey(signWithOtherKey ? otherSigningKey : signingKey) { KeyId = signWithOtherKey ? "other-key" : "stub-key" };
        var exp = expires ?? now.AddMinutes(5);
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Claims = claims,
            IssuedAt = exp.AddMinutes(-10) < now ? exp.AddMinutes(-10) : now,
            NotBefore = exp.AddMinutes(-10) < now ? exp.AddMinutes(-10) : now,
            Expires = exp,
            TokenType = type,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSsaPssSha256)
        });
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var url = request.RequestUri!.GetLeftPart(UriPartial.Path);
        if (url == DiscoveryUrl)
        {
            return Json(HttpStatusCode.OK, new Dictionary<string, object>
            {
                ["issuer"] = DiscoveryIssuer,
                ["jwks_uri"] = JwksUri,
                ["introspection_endpoint"] = IntrospectionEndpoint,
                ["authorization_endpoint"] = Issuer + "/authorize.idp",
                ["token_endpoint"] = Issuer + "/token.idp"
            });
        }

        if (url == JwksUri)
        {
            var parameters = signingKey.ExportParameters(false);
            return Json(HttpStatusCode.OK, new Dictionary<string, object>
            {
                ["keys"] = new[]
                {
                    new Dictionary<string, string>
                    {
                        ["kty"] = "RSA",
                        ["use"] = "sig",
                        ["kid"] = "stub-key",
                        ["n"] = Base64UrlEncoder.Encode(parameters.Modulus),
                        ["e"] = Base64UrlEncoder.Encode(parameters.Exponent)
                    }
                }
            });
        }

        if (url == IntrospectionEndpoint && request.Method == HttpMethod.Post)
        {
            var form = (await request.Content!.ReadAsStringAsync(cancellationToken)).Split('&')
                .Select(pair => pair.Split('='))
                .ToDictionary(pair => WebUtility.UrlDecode(pair[0]), pair => WebUtility.UrlDecode(pair[1]));
            IntrospectionRequests.Enqueue(form);
            return IntrospectionResponder?.Invoke(form) ?? DefaultIntrospectionResponse(form["token"]);
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    private HttpResponseMessage DefaultIntrospectionResponse(string token)
    {
        using var payload = JsonDocument.Parse(Base64UrlEncoder.Decode(new JsonWebToken(token).EncodedPayload));
        var expired = payload.RootElement.GetProperty("exp").GetInt64() < DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (RevokedTokens.ContainsKey(token) || expired)
        {
            return Json(HttpStatusCode.OK, new Dictionary<string, object> { ["active"] = false });
        }

        var response = new Dictionary<string, object>
        {
            ["active"] = true,
            ["client_id"] = ClientId,
            ["token_type"] = "Bearer"
        };
        if (payload.RootElement.TryGetProperty("cnf", out var cnf))
        {
            response["cnf"] = JsonSerializer.Deserialize<Dictionary<string, object>>(cnf.GetRawText())!;
            if (cnf.TryGetProperty("jkt", out _))
            {
                response["token_type"] = "DPoP";
            }
        }

        return Json(HttpStatusCode.OK, response);
    }

    internal static HttpResponseMessage Json(HttpStatusCode status, object body)
    {
        return new HttpResponseMessage(status)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json")
        };
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            signingKey.Dispose();
            otherSigningKey.Dispose();
        }

        base.Dispose(disposing);
    }
}
