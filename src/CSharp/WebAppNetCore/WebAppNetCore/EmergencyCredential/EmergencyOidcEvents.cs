using System;
using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;

namespace WebAppNetCore.EmergencyCredential
{
    public static class EmergencyOidcEvents
    {
        private const string Staged = "oidc-emergency-validated";
        public static Task StageAsync(TokenValidatedContext context)
        {
            EmergencyRuntime runtime = context.HttpContext.RequestServices.GetRequiredService<EmergencyRuntime>();
            if (!runtime.Options.Enabled)
            {
                return Task.CompletedTask;
            }
            context.HttpContext.Items.Remove(Staged);
            string issuer, subject, id;
            long expires;
            JwtSecurityToken jwt = context.SecurityToken;
            if (jwt == null)
            {
                EmergencyDiagnostics.Write(context.HttpContext, "normal_login_capture_skipped", 400);
                return Task.CompletedTask;
            }
            issuer = jwt.Issuer;
            subject = jwt.Subject;
            id = jwt.Id;
            expires = Math.Min(new DateTimeOffset(jwt.ValidTo, TimeSpan.Zero).ToUnixTimeSeconds(), new DateTimeOffset(jwt.IssuedAt, TimeSpan.Zero).ToUnixTimeSeconds() + 86400);
            context.HttpContext.Items[Staged] = new AcceptedLogin { Issuer = issuer, Subject = subject, TokenReference = id, Expires = expires };
            return Task.CompletedTask;
        }
        public static async Task AcceptedAsync(TicketReceivedContext context)
        {
            string sid = context.Principal.FindFirst("sid")?.Value;
            if (!string.IsNullOrEmpty(sid))
            {
                OpenIdConnectHelper.LiveSessions[sid] = true;
            }
            EmergencyRuntime runtime = context.HttpContext.RequestServices.GetRequiredService<EmergencyRuntime>();
            if (!runtime.Options.Enabled)
            {
                return;
            }
            try
            {
                AuthenticateResult previous = await context.HttpContext.AuthenticateAsync(EmergencyExtensions.CookieScheme);
                if (previous.Succeeded)
                {
                    runtime.Service.SignOut(previous.Principal.FindFirst("emergency_session_id")?.Value);
                }
                string browser = EmergencyBrowser.Ensure(context.HttpContext, true);
                context.Properties.Items.Remove("emergency_login");
                if (context.HttpContext.Items.TryGetValue(Staged, out object staged) && staged is AcceptedLogin login)
                {
                    context.Properties.Items["emergency_login"] = runtime.Service.Capture(browser, login.Subject, login.Issuer, login.TokenReference, login.Expires);
                    EmergencyDiagnostics.Write(context.HttpContext, "normal_login_captured");
                }
            }
            catch (Exception exception)
            {
                EmergencyDiagnostics.Write(context.HttpContext, "normal_login_capture_failed", 503, exception);
                // Optional preparation failure must not interrupt an accepted normal login.
                context.Properties.Items.Remove("emergency_login");
            }
            finally
            {
                try
                {
                    await context.HttpContext.SignOutAsync(EmergencyExtensions.CookieScheme);
                }
                catch (Exception) { }
            }
        }
    }
}
