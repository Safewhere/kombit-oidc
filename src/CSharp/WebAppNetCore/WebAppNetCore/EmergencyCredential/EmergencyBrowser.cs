using Microsoft.AspNetCore.Http;

namespace WebAppNetCore.EmergencyCredential
{
    public static class EmergencyBrowser
    {
        private const string Cookie = "__Secure-OidcEmergencyBrowser";
        public static string Read(HttpContext context) => context.Items[Cookie] as string ?? context.Request.Cookies[Cookie];
        public static string Ensure(HttpContext context, bool rotate = false)
        {
            string id = Read(context);
            if (rotate || string.IsNullOrEmpty(id) || id.Length != 43)
            {
                id = StrictJson.Id();
                context.Items[Cookie] = id;
                context.Response.Cookies.Append(Cookie, id, new CookieOptions { Secure = true, HttpOnly = true, SameSite = SameSiteMode.Strict, Path = context.Request.PathBase.HasValue ? context.Request.PathBase.Value : "/", IsEssential = true });
            }
            return id;
        }
    }
}
