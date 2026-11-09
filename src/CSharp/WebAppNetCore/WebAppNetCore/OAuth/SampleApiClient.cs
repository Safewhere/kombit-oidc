using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;

namespace WebAppNetCore.OAuth
{
    public enum SampleApiOperation
    {
        ReadProfile,
        WriteNote
    }

    /// <summary>The status and the body of a response of the sample API.</summary>
    public sealed class SampleApiResult
    {
        public SampleApiResult(int statusCode, string body)
        {
            StatusCode = statusCode;
            Body = body;
        }

        public int StatusCode { get; }

        public string Body { get; }

        /// <summary>The result line of the home page: the JSON body for a success, the error code and description otherwise.</summary>
        public string Describe()
        {
            if (StatusCode >= 200 && StatusCode < 300)
            {
                return "The sample API returned HTTP " + StatusCode + ": " + Body;
            }

            try
            {
                using var document = JsonDocument.Parse(Body);
                var error = document.RootElement.TryGetProperty("error", out var code) ? code.GetString() : null;
                var description = document.RootElement.TryGetProperty("error_description", out var text) ? text.GetString() : null;
                return "The sample API returned HTTP " + StatusCode + ": " + error + (description == null ? string.Empty : " (" + description + ")");
            }
            catch (JsonException)
            {
                return "The sample API returned HTTP " + StatusCode + ".";
            }
        }
    }

    /// <summary>
    /// Calls the sample resource server (SampleApi) with the access token of the session, the DPoP scheme, and a proof with ath
    /// (RFC 9449 section 7.1). The contract is docs/features/US38464/sample-resource-server-contract.md.
    /// </summary>
    public sealed class SampleApiClient
    {
        public const string HttpClientName = "SampleApi";
        public const string ProfilePath = "/api/profile";
        public const string NotesPath = "/api/notes";
        private const string Step = "Sample API request";

        private readonly IHttpClientFactory httpClientFactory;
        private readonly IConfiguration configuration;

        public SampleApiClient(IHttpClientFactory httpClientFactory, IConfiguration configuration)
        {
            this.httpClientFactory = httpClientFactory;
            this.configuration = configuration;
        }

        public async Task<SampleApiResult> SendAsync(SampleApiOperation operation, string noteText, string accessToken, string idToken,
            ClientSession session, Fault fault, CancellationToken cancellationToken)
        {
            var baseUrl = configuration.SampleApiBaseUrl();
            if (string.IsNullOrEmpty(baseUrl))
            {
                throw new OAuthClientException("SampleApi:BaseUrl is not set, so the sample does not call the sample API.");
            }

            var dpopKey = session?.DPoPKey ?? throw new OAuthClientException(
                "The sample API accepts only DPoP-bound access tokens, and the DPoP key of this sign-in is not available. Sign in with DPoP:BindAccessTokens=true.");
            // SampleApiIdToken sends the ID token of the sign-in instead of the access token: a token substitution.
            var token = fault == Fault.SampleApiIdToken ? idToken : accessToken;
            if (string.IsNullOrEmpty(token))
            {
                throw new OAuthClientException(fault == Fault.SampleApiIdToken ? "The session has no ID token." : "The session has no access token.");
            }

            var readProfile = operation == SampleApiOperation.ReadProfile;
            var method = readProfile ? HttpMethod.Get : HttpMethod.Post;
            var url = baseUrl + (readProfile ? ProfilePath : NotesPath);
            using var otherKey = fault == Fault.SampleApiProofOtherKey ? DPoPKey.Create() : null;
            var proof = DPoPProofFactory.Create(
                otherKey ?? dpopKey,
                configuration.DPoPSigningAlgorithm(),
                fault == Fault.SampleApiProofWrongHtm ? (readProfile ? "POST" : "GET") : method.Method,
                fault == Fault.SampleApiProofWrongHtu ? baseUrl + (readProfile ? NotesPath : ProfilePath) : url,
                fault == Fault.SampleApiProofWrongAth ? token + "-other" : token);

            SampleApiResult result = null;
            var requests = fault == Fault.SampleApiReplayProof ? 2 : 1;
            for (var number = 1; number <= requests; number++)
            {
                // SampleApiTokenInQuery sends the token in the access_token query parameter (RFC 6750 section 2.3), which FAPI 2.0
                // section 5.3.4 forbids. SampleApiBearerScheme sends the token with the Bearer scheme and no proof.
                var requestUri = fault == Fault.SampleApiTokenInQuery ? QueryHelpers.AddQueryString(url, "access_token", token) : url;
                using var request = new HttpRequestMessage(method, requestUri);
                if (fault == Fault.SampleApiBearerScheme)
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                }
                else
                {
                    if (fault != Fault.SampleApiTokenInQuery)
                    {
                        request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", token);
                    }

                    request.Headers.Add("DPoP", proof);
                }

                if (!readProfile)
                {
                    request.Content = JsonContent.Create(new { text = noteText });
                }

                using var response = await httpClientFactory.CreateClient(HttpClientName).SendAsync(request, cancellationToken);
                result = new SampleApiResult((int)response.StatusCode, await response.Content.ReadAsStringAsync(cancellationToken));
                var summary = number == 1 && requests == 2
                    ? "fault SampleApiReplayProof: the next call sends the same proof"
                    : result.StatusCode >= 200 && result.StatusCode < 300 ? null : result.Describe();
                session?.Trace.AddExchange(Step, request, null, null, result.StatusCode, summary,
                    response.Headers.WwwAuthenticate.Select(challenge => ProtocolTrace.Detail("WWW-Authenticate", challenge.ToString())));
            }

            return result;
        }
    }
}
