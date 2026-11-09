using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.JsonWebTokens;
using WebAppNetCore.Models;
using WebAppNetCore.OAuth;

namespace WebAppNetCore.Controllers
{
    public class HomeController : Controller
    {
        public IConfiguration Configuration
        {
            get;
            private set;
        }

        private readonly ClientSessionStore sessionStore;
        private readonly IdentifyMetadata identifyMetadata;

        public HomeController(IConfiguration configuration, ClientSessionStore sessionStore, IdentifyMetadata identifyMetadata)
        {
            Configuration = configuration ?? throw new ArgumentNullException("configuration");
            this.sessionStore = sessionStore;
            this.identifyMetadata = identifyMetadata;
        }

        public async Task<IActionResult> Index()
        {
            ViewData["Origin"] = $"{Request.Scheme}://{Request.Host.Value}";

            if(HttpContext.User.Identity.IsAuthenticated)
            {
                ViewData["IdTokenHint"] = HttpContext.GetTokenAsync(OpenIdConnectConstants.IdToken).Result;
                ViewData[OpenIdConnectConstants.AccessToken] = HttpContext.GetTokenAsync(OpenIdConnectConstants.AccessToken).Result;
            }
            else
            {
                ViewData["IdTokenHint"] = null;
                ViewData[OpenIdConnectConstants.AccessToken] = null;
            }

            var callbackUrl = Url.Action("SignedOutCallback", "Account", values: null, protocol: Request.Scheme);
            ViewData["RedirectUrl"] = callbackUrl;

            ViewData["EnableSessionManagement"] = Configuration.EnableSessionManagement() ? "Yes" : "No";
            ViewData["EnablePostLogout"] = Configuration.EnablePostLogout() ? "Yes" : "No";

            var protocol = await CreateProtocolViewModelAsync();
            await SetIdentifyEndpointsAsync(protocol);
            ViewData["Protocol"] = protocol;
            return View();
        }

        /// <summary>
        /// Sets the end-session and check-session URLs from the discovery document, after the issuer check of IdentifyMetadata.
        /// Only a signed-in user sees the post logout form and the session check frames.
        /// </summary>
        private async Task SetIdentifyEndpointsAsync(ProtocolViewModel protocol)
        {
            if (!HttpContext.User.Identity.IsAuthenticated || (!Configuration.EnablePostLogout() && !Configuration.EnableSessionManagement()))
            {
                return;
            }

            try
            {
                var metadata = await identifyMetadata.GetAsync(HttpContext.RequestAborted);
                if (Configuration.EnablePostLogout())
                {
                    ViewData["EndSessionUri"] = IdentifyMetadata.RequireEndpoint(metadata.EndSessionEndpoint, "end_session_endpoint");
                }

                if (Configuration.EnableSessionManagement())
                {
                    ViewData["CheckSessionIframeUri"] = IdentifyMetadata.RequireEndpoint(metadata.CheckSessionIframe, "check_session_iframe");
                }
            }
            catch (Exception exception) when (exception is OAuthClientException || exception is InvalidOperationException)
            {
                protocol.Warnings.Add("The post logout form and the session check are not available: " + exception.Message);
            }
        }
       
        public IActionResult About()
        {
            ViewData["Message"] = "Your application description page.";

            return View();
        }

        public IActionResult Contact()
        {
            ViewData["Message"] = "Your contact page.";

            return View();
        }

        private async Task<ProtocolViewModel> CreateProtocolViewModelAsync()
        {
            var model = new ProtocolViewModel
            {
                BuildingBlocks = Configuration.DescribeBuildingBlocks(),
                Warnings = Configuration.BuildingBlockWarnings(),
                Result = TempData[ProtocolViewModel.ResultKey] as string,
                IsAuthenticated = HttpContext.User.Identity.IsAuthenticated,
                FaultInjectionEnabled = Configuration.EnableFaultInjection()
            };
            if (!model.IsAuthenticated)
            {
                return model;
            }

            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            var accessToken = result.Properties?.GetTokenValue(OpenIdConnectConstants.AccessToken);
            model.TokenType = result.Properties?.GetTokenValue("token_type");
            model.HasRefreshToken = !string.IsNullOrEmpty(result.Properties?.GetTokenValue("refresh_token"));
            model.ExpiresAt = result.Properties?.GetTokenValue("expires_at");
            model.AccessTokenJkt = AccessTokenInspector.ReadConfirmationThumbprint(accessToken);

            var session = sessionStore.Get(result.Properties);
            model.SessionStateAvailable = session != null;
            if (session != null)
            {
                model.DPoPKeyThumbprint = session.DPoPKey?.Thumbprint;
                model.PushedAuthorization = session.PushedAuthorization;
                model.Trace = session.Trace.Entries;
                model.LastUserInfo = session.LastUserInfo;
            }

            return model;
        }

        public IActionResult Error()
        {
            var message = TempData[ErrorPage.MessageKey] as string ?? HttpContext.Items["RemoteError"]?.ToString();
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier, Message = message });
        }    
    }
}
