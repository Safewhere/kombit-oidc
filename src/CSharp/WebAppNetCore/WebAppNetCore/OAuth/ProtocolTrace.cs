using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace WebAppNetCore.OAuth
{
    /// <summary>
    /// A record of the protocol messages of one sign-in, for the home page. It never contains client secrets, private keys,
    /// code verifiers, or JWT signatures: JWTs are shown as decoded header and payload.
    /// </summary>
    public sealed class ProtocolTrace
    {
        private const int MaximumEntries = 50;
        private static readonly JsonSerializerOptions IndentedJson = new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        private readonly List<ProtocolTraceEntry> entries = new List<ProtocolTraceEntry>();

        public IReadOnlyList<ProtocolTraceEntry> Entries
        {
            get
            {
                lock (entries)
                {
                    return entries.ToList();
                }
            }
        }

        public void Add(string step, string summary, IEnumerable<KeyValuePair<string, string>> details = null)
        {
            var entry = new ProtocolTraceEntry(DateTimeOffset.UtcNow, step, summary, details?.ToList() ?? new List<KeyValuePair<string, string>>());
            lock (entries)
            {
                entries.Add(entry);
                if (entries.Count > MaximumEntries)
                {
                    entries.RemoveAt(0);
                }
            }
        }

        /// <summary>
        /// Records one HTTP exchange with an Identify endpoint: the request line, the authorization scheme, the redacted form,
        /// the decoded client assertion and DPoP proof, and the response.
        /// </summary>
        public void AddExchange(
            string step,
            HttpRequestMessage request,
            IDictionary<string, string> form,
            string clientAssertion,
            int statusCode,
            string responseSummary,
            IEnumerable<KeyValuePair<string, string>> responseDetails = null)
        {
            var details = new List<KeyValuePair<string, string>> { Detail("Request", request.Method + " " + request.RequestUri) };
            if (request.Headers.Authorization != null)
            {
                var credentials = string.Equals(request.Headers.Authorization.Scheme, "Basic", StringComparison.OrdinalIgnoreCase)
                    ? "(client credentials)"
                    : "(access token)";
                details.Add(Detail("Authorization header", request.Headers.Authorization.Scheme + " " + credentials));
            }

            if (form != null)
            {
                details.AddRange(form.Select(p => Detail("Form " + p.Key, RedactFormValue(p.Key, p.Value))));
            }

            if (clientAssertion != null)
            {
                details.Add(Detail("Client assertion", DescribeJwt(clientAssertion)));
            }

            if (request.Headers.TryGetValues("DPoP", out var proofs))
            {
                details.Add(Detail("DPoP proof", DescribeJwt(proofs.First())));
            }

            details.Add(Detail("Response", "HTTP " + statusCode + (string.IsNullOrEmpty(responseSummary) ? string.Empty : " " + responseSummary)));
            if (responseDetails != null)
            {
                details.AddRange(responseDetails);
            }

            Add(step, "HTTP " + statusCode + (string.IsNullOrEmpty(responseSummary) ? string.Empty : ": " + responseSummary), details);
        }

        public static KeyValuePair<string, string> Detail(string name, string value) => new KeyValuePair<string, string>(name, value);

        /// <summary>
        /// The decoded header and payload of a JWT, without the signature.
        /// </summary>
        public static string DescribeJwt(string jwt)
        {
            var parts = jwt?.Split('.');
            if (parts == null || parts.Length < 2)
            {
                return "(not a JWT)";
            }

            if (parts.Length == 5)
            {
                return "(encrypted JWT) header: " + FormatJson(Base64UrlEncoder.Decode(parts[0]));
            }

            return "header: " + FormatJson(Base64UrlEncoder.Decode(parts[0])) + Environment.NewLine
                + "payload: " + FormatJson(Base64UrlEncoder.Decode(parts[1]));
        }

        public static string FormatJson(string json)
        {
            try
            {
                using var document = JsonDocument.Parse(json);
                return JsonSerializer.Serialize(document.RootElement, IndentedJson);
            }
            catch (JsonException)
            {
                return json;
            }
        }

        private static string RedactFormValue(string name, string value)
        {
            switch (name)
            {
                case "client_secret":
                case "code_verifier":
                    return "(redacted)";
                case "client_assertion":
                    return "(see Client assertion)";
                case "code":
                case "refresh_token":
                    return "(present)";
                case "state":
                    return "(protected authentication properties, " + value?.Length + " characters)";
                default:
                    return value;
            }
        }
    }

    public sealed class ProtocolTraceEntry
    {
        public ProtocolTraceEntry(DateTimeOffset time, string step, string summary, IReadOnlyList<KeyValuePair<string, string>> details)
        {
            Time = time;
            Step = step;
            Summary = summary;
            Details = details;
        }

        public DateTimeOffset Time { get; }

        public string Step { get; }

        public string Summary { get; }

        public IReadOnlyList<KeyValuePair<string, string>> Details { get; }
    }
}
