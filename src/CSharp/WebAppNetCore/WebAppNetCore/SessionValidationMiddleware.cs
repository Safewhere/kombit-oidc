using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;

namespace WebAppNetCore
{
    public class SessionValidationMiddleware
    {
        private readonly RequestDelegate _next;

        public SessionValidationMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Check if user is authenticated
            if (context.User.Identity.IsAuthenticated)
            {
                var sid = context.User.FindFirst(OpenIdConnectConstants.SessionId)?.Value;

                if (!string.IsNullOrEmpty(sid) &&
                    OpenIdConnectHelper.LiveSessions.ContainsKey(sid) &&
                    OpenIdConnectHelper.LiveSessions[sid] == false)
                {
                    // Session is invalid, sign out and redirect
                    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    context.Response.Redirect("/Account/SignedOut");
                    return; // Don't continue with the request
                }
            }

            // Continue with normal request processing
            await _next(context);
        }
    }

}
