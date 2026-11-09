namespace SampleApi;

/// <summary>
/// A rejected request (contract section 7). The description is a fixed text that contains no value from the request. The
/// reason is for the log only.
/// </summary>
public sealed class ProtectedResourceException : Exception
{
    private ProtectedResourceException(int statusCode, string? error, string description, string reason)
        : base(description)
    {
        StatusCode = statusCode;
        Error = error;
        Reason = reason;
    }

    public int StatusCode { get; }

    /// <summary>The error code of the challenge, or null when the response has no error code.</summary>
    public string? Error { get; }

    public string Reason { get; }

    public static ProtectedResourceException InvalidRequest(string reason) =>
        new(StatusCodes.Status400BadRequest, "invalid_request", "The request is not valid.", reason);

    public static ProtectedResourceException InvalidToken(string reason) =>
        new(StatusCodes.Status401Unauthorized, "invalid_token", "The access token is not valid.", reason);

    public static ProtectedResourceException InvalidProof(string reason) =>
        new(StatusCodes.Status401Unauthorized, "invalid_dpop_proof", "The DPoP proof is not valid.", reason);

    public static ProtectedResourceException Unavailable(string reason) =>
        new(StatusCodes.Status503ServiceUnavailable, null, "The authorization server cannot check the access token now.", reason);
}

/// <summary>
/// The WWW-Authenticate value of the DPoP scheme (RFC 9449 section 7.1).
/// </summary>
public static class DPoPChallenge
{
    public const string Algorithms = "PS256";

    public static string Create(string? error, string? scope = null)
    {
        var parameters = new List<string>();
        if (error is not null)
        {
            parameters.Add($"error=\"{error}\"");
        }

        if (scope is not null)
        {
            parameters.Add($"scope=\"{scope}\"");
        }

        parameters.Add($"algs=\"{Algorithms}\"");
        return "DPoP " + string.Join(", ", parameters);
    }
}
