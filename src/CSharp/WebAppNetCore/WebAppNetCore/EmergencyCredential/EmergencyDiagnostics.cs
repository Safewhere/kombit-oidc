using System;
using System.Linq;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace WebAppNetCore.EmergencyCredential
{
    public static class EmergencyDiagnostics
    {
        private static readonly object ReferenceKey = new object();
        public static string Reference(HttpContext context)
        {
            if (!(context.Items[ReferenceKey] is string reference))
            {
                reference = Guid.NewGuid().ToString("N");
                context.Items[ReferenceKey] = reference;
            }
            if (!context.Response.HasStarted) context.Response.Headers["X-Emergency-Reference"] = reference;
            return reference;
        }
        public static void Write(HttpContext context, string eventName, int status = 200, Exception exception = null, long elapsedMilliseconds = 0, object[] issuerCalls = null)
        {
            try
            {
                string reference = Reference(context);
                var logger = context.RequestServices.GetService<ILoggerFactory>()?.CreateLogger("WebAppNetCore.EmergencyCredential.Diagnostics");
                if (logger == null) return;
                var types = new System.Collections.Generic.List<object>();
                for (var current = exception; current != null && types.Count < 8; current = current.InnerException)
                    types.Add(new { type = current.GetType().FullName, hresult = current.HResult });
                var fault = exception as EmergencyFault;
                string text = JsonSerializer.Serialize(new {
                    @event = eventName, reference_id = reference, timestamp_utc = DateTimeOffset.UtcNow,
                    endpoint = Endpoint(context.Request.Path.Value), method = context.Request.Method == "GET" ? "GET" : context.Request.Method == "POST" ? "POST" : "OTHER",
                    status, elapsed_ms = elapsedMilliseconds, error = fault?.Code, exceptions = types,
                    issuer_calls = issuerCalls ?? Array.Empty<object>()
                });
                if (status >= 500) logger.LogError("{EmergencyEvent}", text);
                else if (status >= 400) logger.LogWarning("{EmergencyEvent}", text);
                else logger.LogInformation("{EmergencyEvent}", text);
            }
            catch (Exception) { /* Diagnostics must never change authentication behavior. */ }
        }
        public static string Endpoint(string path)
        {
            switch (path)
            {
                case "/emergency": case "/emergency/login": case "/emergency/home": case "/emergency/ended":
                case "/emergency/normal-login": case "/emergency/enrollments": case "/emergency/renewals":
                case "/emergency/status": case "/emergency/possession/options": case "/emergency/possession/complete":
                case "/emergency/login/status": case "/emergency/login/options": case "/emergency/login/complete": case "/emergency/signout": return path;
            }
            if (path != null && path.StartsWith("/emergency/enrollments/", StringComparison.Ordinal))
            {
                if (path.EndsWith("/complete", StringComparison.Ordinal)) return "/emergency/enrollments/{id}/complete";
                if (path.EndsWith("/cancel", StringComparison.Ordinal)) return "/emergency/enrollments/{id}/cancel";
            }
            if (path != null && path.StartsWith("/emergency/keys/", StringComparison.Ordinal) && path.EndsWith("/remove", StringComparison.Ordinal)) return "/emergency/keys/{id}/remove";
            return "other";
        }
    }
}
