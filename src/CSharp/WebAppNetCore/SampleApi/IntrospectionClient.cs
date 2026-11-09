using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace SampleApi;

/// <summary>
/// The result of introspection that the API uses (RFC 7662 section 2.2).
/// </summary>
public sealed record IntrospectionResult(bool Active, string? TokenType, string? Jkt, string? ClientId);

/// <summary>
/// Calls the introspection endpoint of Identify for each request, with the client assertion of the API connection (contract section 6
/// step 5). It keeps no cache, so a revocation takes effect at the next request.
/// </summary>
public sealed class IntrospectionClient
{
    private readonly IHttpClientFactory httpClientFactory;
    private readonly IdentifyMetadata metadata;
    private readonly ClientAssertionFactory assertionFactory;
    private readonly SampleApiOptions options;

    public IntrospectionClient(IHttpClientFactory httpClientFactory, IdentifyMetadata metadata, ClientAssertionFactory assertionFactory,
        IOptions<SampleApiOptions> options)
    {
        this.httpClientFactory = httpClientFactory;
        this.metadata = metadata;
        this.assertionFactory = assertionFactory;
        this.options = options.Value;
    }

    public async Task<IntrospectionResult> IntrospectAsync(string accessToken, CancellationToken cancellationToken)
    {
        var configuration = await metadata.GetAsync(cancellationToken);
        if (string.IsNullOrEmpty(configuration.IntrospectionEndpoint))
        {
            throw ProtectedResourceException.Unavailable("The discovery document has no introspection_endpoint.");
        }

        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = accessToken,
            ["token_type_hint"] = "access_token",
            ["client_id"] = options.ClientId,
            ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ["client_assertion"] = assertionFactory.Create(options.ClientId, options.NormalizedIssuer)
        });

        HttpResponseMessage response;
        try
        {
            response = await httpClientFactory.CreateClient(IdentifyMetadata.HttpClientName)
                .PostAsync(configuration.IntrospectionEndpoint, content, cancellationToken);
        }
        catch (HttpRequestException exception)
        {
            throw ProtectedResourceException.Unavailable("The introspection request failed: " + exception.Message);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                throw ProtectedResourceException.Unavailable("The introspection endpoint returned HTTP " + (int)response.StatusCode + ".");
            }

            try
            {
                using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
                var root = document.RootElement;
                var active = root.TryGetProperty("active", out var activeElement) && activeElement.ValueKind == JsonValueKind.True;
                string? jkt = null;
                if (root.TryGetProperty("cnf", out var confirmation) && confirmation.ValueKind == JsonValueKind.Object
                    && confirmation.TryGetProperty("jkt", out var jktElement) && jktElement.ValueKind == JsonValueKind.String)
                {
                    jkt = jktElement.GetString();
                }

                return new IntrospectionResult(active, ReadString(root, "token_type"), jkt, ReadString(root, "client_id"));
            }
            catch (JsonException exception)
            {
                throw ProtectedResourceException.Unavailable("The introspection response is not JSON: " + exception.Message);
            }
        }
    }

    private static string? ReadString(JsonElement element, string name)
    {
        return element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    }
}

/// <summary>
/// Creates the private_key_jwt client assertion of the API connection: PS256, aud is the issuer (FAPI 2.0 section 5.3.2.1 item 8).
/// </summary>
public sealed class ClientAssertionFactory
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(60);
    private readonly JsonWebTokenHandler handler = new() { SetDefaultTimesOnTokenCreation = false };
    private readonly SigningCredentials credentials;
    private readonly TimeProvider timeProvider;

    public ClientAssertionFactory(X509Certificate2 certificate, TimeProvider timeProvider)
    {
        if (!certificate.HasPrivateKey)
        {
            throw new InvalidOperationException("The certificate of the client assertion has no private key.");
        }

        // The kid is the base64url SHA-1 hash of the certificate, as in the JWKS of the API connection.
        var key = new X509SecurityKey(certificate) { KeyId = Base64UrlEncoder.Encode(certificate.GetCertHash()) };
        credentials = new SigningCredentials(key, SecurityAlgorithms.RsaSsaPssSha256);
        this.timeProvider = timeProvider;
    }

    public static ClientAssertionFactory FromSettings(SampleApiOptions options, TimeProvider timeProvider)
    {
        if (string.IsNullOrEmpty(options.AssertionSigningCertPath))
        {
            throw new InvalidOperationException("SampleApi:AssertionSigningCertPath is not set. Set it and its password in user secrets.");
        }

        return new ClientAssertionFactory(
            X509CertificateLoader.LoadPkcs12FromFile(options.AssertionSigningCertPath, options.AssertionSigningCertPassword), timeProvider);
    }

    public string Create(string clientId, string audience)
    {
        var now = timeProvider.GetUtcNow().UtcDateTime;
        return handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = clientId,
            Audience = audience,
            Claims = new Dictionary<string, object>
            {
                ["sub"] = clientId,
                ["jti"] = Guid.NewGuid().ToString(),
                ["iat"] = EpochTime.GetIntDate(now),
                ["nbf"] = EpochTime.GetIntDate(now),
                ["exp"] = EpochTime.GetIntDate(now.Add(Lifetime))
            },
            SigningCredentials = credentials,
            TokenType = "JWT"
        });
    }
}
