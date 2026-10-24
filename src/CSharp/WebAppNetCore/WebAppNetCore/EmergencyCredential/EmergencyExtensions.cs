using System;
using System.IO;
using System.Net.Http;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace WebAppNetCore.EmergencyCredential
{
    public static class EmergencyExtensions
    {
        public const string CookieScheme = "EmergencyCookie";
        public static void AddEmergencyCredential(this IServiceCollection services, IConfiguration configuration)
        {
            EmergencyOptions options = new EmergencyOptions();
            configuration.GetSection("EmergencyCredential").Bind(options);
            services.AddSingleton(options);
            services.AddAntiforgery(antiforgery => { antiforgery.HeaderName = "X-Emergency-CSRF"; antiforgery.Cookie.SecurePolicy = CookieSecurePolicy.Always; antiforgery.Cookie.SameSite = SameSiteMode.Strict; });
            services.AddHttpClient("EmergencyIssuer", client => client.Timeout = TimeSpan.FromSeconds(8))
                .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false });
            // This provider protects emergency state only. Normal authentication keeps its existing provider.
            services.AddSingleton<EmergencyProtection>(provider => new EmergencyProtection(options));
            services.AddSingleton(provider => new EmergencyRuntime(options, provider.GetRequiredService<EmergencyProtection>().Provider,
                provider.GetRequiredService<IHttpClientFactory>(), provider.GetRequiredService<Microsoft.AspNetCore.Hosting.IWebHostEnvironment>(), provider.GetRequiredService<Microsoft.Extensions.Logging.ILogger<EmergencyRuntime>>()));
            services.AddAuthentication().AddCookie(CookieScheme, ConfigureCookie);
        }
        private static void ConfigureCookie(CookieAuthenticationOptions options)
        {
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.SlidingExpiration = false;
            options.Events.OnRedirectToLogin = context => { context.Response.StatusCode = 401; return System.Threading.Tasks.Task.CompletedTask; };
            options.Events.OnRedirectToAccessDenied = context => { context.Response.StatusCode = 403; return System.Threading.Tasks.Task.CompletedTask; };
        }
    }
}
