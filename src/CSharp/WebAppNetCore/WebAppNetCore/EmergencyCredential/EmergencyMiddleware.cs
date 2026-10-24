using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace WebAppNetCore.EmergencyCredential
{
    public sealed class EmergencyMiddleware
    {
        private readonly RequestDelegate next;
        public EmergencyMiddleware(RequestDelegate pipeline)
        {
            next = pipeline;
        }
        public async Task InvokeAsync(HttpContext context, EmergencyRuntime runtime)
        {
            if (!context.Request.Path.StartsWithSegments("/emergency")) { await InvokeCoreAsync(context, runtime); return; }
            var timer = System.Diagnostics.Stopwatch.StartNew();
            bool failed = false;
            EmergencyDiagnostics.Write(context, "request_started");
            try { await InvokeCoreAsync(context, runtime); }
            catch (Exception exception) { failed = true; EmergencyDiagnostics.Write(context, "request_failed", 500, exception); throw; }
            finally { EmergencyDiagnostics.Write(context, "request_completed", failed ? 500 : context.Response.StatusCode, elapsedMilliseconds: timer.ElapsedMilliseconds); }
        }
        private async Task InvokeCoreAsync(HttpContext context, EmergencyRuntime runtime)
        {
            bool featurePath = context.Request.Path.StartsWithSegments("/emergency");
            if (featurePath)
            {
                context.Response.Headers.CacheControl = "no-store";
                context.Response.Headers["X-Content-Type-Options"] = "nosniff";
                context.Response.Headers["X-Frame-Options"] = "DENY";
                context.Response.Headers["Referrer-Policy"] = "same-origin";
                context.Response.Headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";
                if (!runtime.Options.Enabled)
                {
                    context.Response.StatusCode = 404;
                    await context.Response.WriteAsJsonAsync(new
                    {
                        error = "not_found"
                    });
                    return;
                }
                if (!context.Request.IsHttps || context.Request.Scheme + "://" + context.Request.Host != runtime.Options.Origin)
                {
                    context.Response.StatusCode = 403;
                    await context.Response.WriteAsJsonAsync(new
                    {
                        error = "https_origin_required"
                    });
                    return;
                }
            }
            AuthenticateResult emergency = await context.AuthenticateAsync(EmergencyExtensions.CookieScheme);
            if (emergency.Succeeded)
            {
                ClaimsPrincipal principal = null;
                try
                {
                    if (runtime.Options.Enabled)
                    {
                        principal = runtime.Service.Session(emergency.Principal.FindFirst("emergency_session_id")?.Value, EmergencyBrowser.Read(context));
                    }
                }
                catch (Exception) { }
                if (principal == null)
                {
                    await context.SignOutAsync(EmergencyExtensions.CookieScheme);
                }
                else if (context.User.Identity?.IsAuthenticated != true)
                {
                    context.User = principal;
                }
            }
            if (context.User.Identity?.IsAuthenticated != true && context.Request.Cookies.ContainsKey(".AspNetCore.EmergencyCookie") && !featurePath)
            {
                await context.SignOutAsync(EmergencyExtensions.CookieScheme);
                context.Response.Redirect(context.Request.PathBase + "/emergency/ended");
                return;
            }
            await next(context);
        }
        public static bool IsEmergency(ClaimsPrincipal principal) => principal.Identity?.AuthenticationType == EmergencyService.AuthenticationType;
    }
}
