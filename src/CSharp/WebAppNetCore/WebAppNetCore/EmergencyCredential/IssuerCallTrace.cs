using System;
using System.Collections.Generic;
using System.Threading;

namespace WebAppNetCore.EmergencyCredential
{
    // Request-scoped, bounded metadata only. Never retain request/response bodies or identifiers.
    public sealed class IssuerCallTrace : IDisposable
    {
        private static readonly AsyncLocal<IssuerCallTrace> current = new AsyncLocal<IssuerCallTrace>();
        private readonly IssuerCallTrace previous;
        private readonly List<object> calls = new List<object>();
        public IssuerCallTrace()
        {
            previous = current.Value;
            current.Value = this;
        }
        public object[] Snapshot()
        {
            lock (calls)
            {
                return calls.ToArray();
            }
        }
        public static void Record(string method, string relative, int? status, long milliseconds, bool received)
        {
            IssuerCallTrace trace = current.Value;
            if (trace == null)
            {
                return;
            }
            string path = relative.Split('?')[0];
            if (path.StartsWith("emergency/enrollments/", StringComparison.Ordinal))
                path = path.EndsWith("/complete", StringComparison.Ordinal) ? "emergency/enrollments/{id}/complete" : "emergency/enrollments/{id}";
            string summary;
            switch (path)
            {
                case "emergency/signing-keys":
                    summary = "Public signing-key response received";
                    break;
                case "emergency/enrollments":
                    summary = "Enrollment and WebAuthn registration options received";
                    break;
                case "emergency/enrollments/{id}/complete":
                case "emergency/renewals":
                    summary = "Encrypted emergency credential received; local validation follows";
                    break;
                case "emergency/enrollments/{id}":
                    summary = "Enrollment cancellation acknowledged";
                    break;
                case "emergency/revocations":
                    summary = method == "GET" ? "Revocation page received; local application follows" : "Revocation acknowledged";
                    break;
                default:
                    path = "emergency/(other)";
                    summary = "Response received";
                    break;
            }
            if (received && status == 204)
                summary = "Operation acknowledged (no response body)";
            if (!received)
                summary = !status.HasValue ? "No HTTP response (transport, cancellation, or local request failure)" : status < 200 || status >= 300 ? "Issuer returned an unsuccessful HTTP status" : "HTTP response received but body could not be accepted";
            if (method != "GET" && method != "POST" && method != "DELETE")
                method = "OTHER";
            lock (trace.calls)
            {
                // Keep headers small even when synchronization paginates. Retain the latest calls.
                if (trace.calls.Count == 8)
                    trace.calls.RemoveAt(0);
                trace.calls.Add(new
                {
                    method,
                    endpoint = path,
                    status,
                    milliseconds,
                    summary
                });
            }
        }
        public void Dispose()
        {
            current.Value = previous;
        }
    }
}
