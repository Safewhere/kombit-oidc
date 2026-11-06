using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WebAppNetCore.OAuth;

namespace WebAppNetCore.Tests;

/// <summary>
/// A programmable stand-in for the Identify endpoints that the sample calls itself: PAR, token, and UserInfo.
/// It records every request, and by default it answers like a successful Identify.
/// </summary>
internal sealed class StubIdentify : HttpMessageHandler
{
    // The same path layout as an Identify Runtime.
    internal const string Domain = "https://provider.test";
    internal const string Issuer = Domain + "/runtime/oauth2";
    internal const string AuthorizationEndpoint = Issuer + "/authorize.idp";
    internal const string TokenEndpoint = Issuer + "/token.idp";
    internal const string ParEndpoint = Issuer + "/par.idp";
    internal const string UserInfoEndpoint = Domain + "/runtime/openidconnect/userinfo.idp";
    internal const string IntrospectionEndpoint = Issuer + "/introspect.idp";
    internal const string RevocationEndpoint = Issuer + "/revoke.idp";
    internal const string EndSessionEndpoint = Domain + "/runtime/openidconnect/logout.idp";

    // The mTLS endpoint aliases of mtls_endpoint_aliases (RFC 8705 section 5), with the same layout as an Identify Runtime.
    internal const string MtlsTokenEndpoint = Issuer + "/mtls/token.idp";
    internal const string MtlsParEndpoint = Issuer + "/mtls/par.idp";
    internal const string MtlsIntrospectionEndpoint = Issuer + "/mtls/introspect.idp";
    internal const string MtlsRevocationEndpoint = Issuer + "/mtls/revoke.idp";
    internal const string MtlsUserInfoEndpoint = Issuer + "/mtls/userinfo.idp";

    /// <summary>
    /// The header that the test HttpClient for mutual TLS adds in place of the TLS client certificate. Its value is the x5t#S256
    /// value of the certificate.
    /// </summary>
    internal const string ClientCertificateHeader = "X-Test-Client-Certificate";

    private static readonly Dictionary<string, string> NormalEndpointsOfAliases = new()
    {
        [MtlsTokenEndpoint] = TokenEndpoint,
        [MtlsParEndpoint] = ParEndpoint,
        [MtlsIntrospectionEndpoint] = IntrospectionEndpoint,
        [MtlsRevocationEndpoint] = RevocationEndpoint,
        [MtlsUserInfoEndpoint] = UserInfoEndpoint
    };
    internal const string RequestUri = "urn:ietf:params:oauth:request_uri:stub-request";
    internal const string Subject = "user-1";
    internal const string SessionId = "session-1";
    internal const string RefreshToken = "refresh-token-1";

    private readonly List<RecordedRequest> requests = new();

    internal StubIdentify(string clientId)
    {
        ClientId = clientId;
        SigningKey = new RsaSecurityKey(RSA.Create(2048)) { KeyId = "stub-signing-key" };
    }

    internal string ClientId { get; }

    internal RsaSecurityKey SigningKey { get; }

    /// <summary>The algorithm of the ID tokens and access tokens that the stub issues.</summary>
    internal string TokenSigningAlgorithm { get; set; } = SecurityAlgorithms.RsaSha256;

    /// <summary>
    /// The nonce of an ID token for a code that was not registered with RegisterCode.
    /// </summary>
    internal string? Nonce { get; set; }

    /// <summary>
    /// Whether the default token response binds the access token to the client certificate of a request at an mTLS alias
    /// (cnf.x5t#S256), as Identify does.
    /// </summary>
    internal bool BindAccessTokensToCertificate { get; set; } = true;

    /// <summary>
    /// Whether the default UserInfo response rejects an access token with cnf.x5t#S256 that comes without the client certificate of
    /// that thumbprint, with HTTP 401 invalid_token (RFC 8705 section 3), as Identify does. An older Identify without the UserInfo
    /// alias accepts such a token.
    /// </summary>
    internal bool CheckCertificateBindingAtUserInfo { get; set; } = true;

    /// <summary>The access tokens that the default token response issued, by authorization code.</summary>
    internal ConcurrentDictionary<string, string> AccessTokensByCode { get; } = new();

    private ConcurrentDictionary<string, string?> NoncesByCode { get; } = new();

    /// <summary>
    /// Registers the nonce for the ID token of an authorization code, so that concurrent flows get their own nonce.
    /// </summary>
    internal void RegisterCode(string code, string? nonce) => NoncesByCode[code] = nonce;

    internal Func<RecordedRequest, HttpResponseMessage>? ParResponder { get; set; }

    internal Func<RecordedRequest, HttpResponseMessage>? TokenResponder { get; set; }

    internal Func<RecordedRequest, HttpResponseMessage>? UserInfoResponder { get; set; }

    internal Func<RecordedRequest, HttpResponseMessage>? IntrospectionResponder { get; set; }

    internal Func<RecordedRequest, HttpResponseMessage>? RevocationResponder { get; set; }

    internal IReadOnlyList<RecordedRequest> Requests
    {
        get
        {
            lock (requests)
            {
                return requests.ToList();
            }
        }
    }

    internal IReadOnlyList<RecordedRequest> RequestsTo(string url) => Requests.Where(r => r.Url == url).ToList();

    internal string IssueIdToken(string? nonce = null, string sessionId = SessionId)
    {
        var claims = new Dictionary<string, object>
        {
            ["sub"] = Subject,
            ["sid"] = sessionId,
            ["name"] = "Test User"
        };
        if (nonce != null)
        {
            claims["nonce"] = nonce;
        }

        return IssueToken(claims);
    }

    internal string IssueAccessToken(string? jkt = null, string? certificateThumbprint = null)
    {
        var claims = new Dictionary<string, object>
        {
            ["sub"] = Subject,
            ["scope"] = "openid",
            ["jti"] = Guid.NewGuid().ToString("N")
        };
        var confirmation = new Dictionary<string, object>();
        if (jkt != null)
        {
            confirmation["jkt"] = jkt;
        }

        if (certificateThumbprint != null)
        {
            confirmation["x5t#S256"] = certificateThumbprint;
        }

        if (confirmation.Count > 0)
        {
            claims["cnf"] = confirmation;
        }

        return IssueToken(claims);
    }

    internal static HttpResponseMessage Json(HttpStatusCode status, object body)
    {
        return new HttpResponseMessage(status)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json")
        };
    }

    internal static HttpResponseMessage OAuthError(HttpStatusCode status, string error, string description)
    {
        return Json(status, new Dictionary<string, string> { ["error"] = error, ["error_description"] = description });
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var recorded = await RecordedRequest.CreateAsync(request);
        lock (requests)
        {
            requests.Add(recorded);
        }

        var endpoint = recorded.Url;
        if (NormalEndpointsOfAliases.TryGetValue(recorded.Url, out var normalEndpoint))
        {
            // Like IIS with SslRequireCert: an mTLS alias rejects a request without a client certificate before Identify sees it.
            if (recorded.Header(ClientCertificateHeader) == null)
            {
                return new HttpResponseMessage(HttpStatusCode.Forbidden)
                {
                    Content = new StringContent("<html><body><h1>403.7 - Forbidden: client certificate required</h1></body></html>", Encoding.UTF8, "text/html")
                };
            }

            endpoint = normalEndpoint;
        }

        return endpoint switch
        {
            ParEndpoint => (ParResponder ?? DefaultParResponse)(recorded),
            TokenEndpoint => (TokenResponder ?? DefaultTokenResponse)(recorded),
            UserInfoEndpoint => (UserInfoResponder ?? DefaultUserInfoResponse)(recorded),
            IntrospectionEndpoint => (IntrospectionResponder ?? DefaultIntrospectionResponse)(recorded),
            RevocationEndpoint => RevocationResponder?.Invoke(recorded) ?? new HttpResponseMessage(HttpStatusCode.OK),
            _ => throw new InvalidOperationException($"Unexpected request to the stub Identify: {request.Method} {request.RequestUri}")
        };
    }

    // The HttpClient factory disposes expired handler chains. The stub outlives them, because each test factory owns one stub.
    protected override void Dispose(bool disposing)
    {
    }

    internal HttpResponseMessage DefaultParResponse(RecordedRequest request)
    {
        return Json(HttpStatusCode.Created, new Dictionary<string, object> { ["request_uri"] = RequestUri, ["expires_in"] = 60 });
    }

    internal HttpResponseMessage DefaultTokenResponse(RecordedRequest request)
    {
        var code = request.Form.GetValueOrDefault("code");
        var nonce = code != null && NoncesByCode.TryGetValue(code, out var registeredNonce) ? registeredNonce : Nonce;
        // Like Identify, a request with a DPoP proof gets an access token that is bound to the proof key.
        var proof = request.Header("DPoP");
        var jkt = proof == null ? null : DPoPProof.Read(proof).Thumbprint;
        // Like Identify, a request that the client certificate authenticated gets an access token that is bound to the certificate.
        var certificateThumbprint = BindAccessTokensToCertificate ? request.Header(ClientCertificateHeader) : null;
        var accessToken = IssueAccessToken(jkt, certificateThumbprint);
        if (code != null)
        {
            AccessTokensByCode[code] = accessToken;
        }

        var body = new Dictionary<string, object>
        {
            ["access_token"] = accessToken,
            ["token_type"] = jkt == null ? "Bearer" : "DPoP",
            ["expires_in"] = 300,
            ["id_token"] = IssueIdToken(nonce, code == null ? SessionId : "session-" + code),
            ["refresh_token"] = RefreshToken
        };
        return Json(HttpStatusCode.OK, body);
    }

    internal HttpResponseMessage DefaultUserInfoResponse(RecordedRequest request)
    {
        var authorization = request.Header("Authorization");
        var accessToken = authorization?.Split(' ', 2).ElementAtOrDefault(1) ?? request.Form.GetValueOrDefault("access_token");
        var boundThumbprint = accessToken == null ? null : AccessTokenInspector.ReadCertificateThumbprint(accessToken);
        if (CheckCertificateBindingAtUserInfo && boundThumbprint != null && boundThumbprint != request.Header(ClientCertificateHeader))
        {
            var response = OAuthError(HttpStatusCode.Unauthorized, "invalid_token", "The specified access token is not valid.");
            response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue("Bearer", "error=\"invalid_token\""));
            return response;
        }

        return Json(HttpStatusCode.OK, new Dictionary<string, object> { ["sub"] = Subject, ["email"] = "user@provider.test" });
    }

    internal HttpResponseMessage DefaultIntrospectionResponse(RecordedRequest request)
    {
        return Json(HttpStatusCode.OK, new Dictionary<string, object> { ["active"] = true, ["token_type"] = "DPoP", ["client_id"] = ClientId });
    }

    internal string IssueToken(Dictionary<string, object> claims)
    {
        var now = DateTime.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = ClientId,
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddMinutes(5),
            Claims = claims,
            SigningCredentials = new SigningCredentials(SigningKey, TokenSigningAlgorithm)
        };
        return new JsonWebTokenHandler().CreateToken(descriptor);
    }
}

internal sealed class RecordedRequest
{
    private RecordedRequest(HttpMethod method, string url, string query, Dictionary<string, string> headers, Dictionary<string, string> form)
    {
        Method = method;
        Url = url;
        Query = query;
        Headers = headers;
        Form = form;
    }

    internal HttpMethod Method { get; }

    /// <summary>The request URL without the query.</summary>
    internal string Url { get; }

    internal string Query { get; }

    internal Dictionary<string, string> Headers { get; }

    internal Dictionary<string, string> Form { get; }

    internal string? Header(string name) => Headers.TryGetValue(name, out var value) ? value : null;

    internal static async Task<RecordedRequest> CreateAsync(HttpRequestMessage request)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in request.Headers)
        {
            headers[header.Key] = string.Join(",", header.Value);
        }

        var form = new Dictionary<string, string>(StringComparer.Ordinal);
        if (request.Content != null)
        {
            foreach (var header in request.Content.Headers)
            {
                headers[header.Key] = string.Join(",", header.Value);
            }

            var body = await request.Content.ReadAsStringAsync();
            foreach (var pair in QueryHelpers.ParseQuery(body))
            {
                form[pair.Key] = pair.Value.ToString();
            }
        }

        var uri = request.RequestUri!;
        return new RecordedRequest(request.Method, uri.GetLeftPart(UriPartial.Path), uri.Query, headers, form);
    }
}
