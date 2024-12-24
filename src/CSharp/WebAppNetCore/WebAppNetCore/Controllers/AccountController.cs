using System;
using System.Linq;
using System.Net.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

namespace WebAppNetCore.Controllers
{
    public class AccountController : Controller
    {
        private HttpClient httpClient;

        private IConfiguration configuration;
        public AccountController(IConfiguration configuration)
        {
            this.configuration = configuration;
            this.httpClient = new HttpClient()
            {
                BaseAddress = new Uri(configuration.ClaimsIssuer())
            };
        }

        // GET: /Account/SignIn
        [HttpGet]
        public IActionResult SignIn()
        {
            return Challenge(
                new AuthenticationProperties { RedirectUri = "/" }, OpenIdConnectDefaults.AuthenticationScheme);
        }

        // GET: /Account/SignOut
        [HttpGet]
        public IActionResult SignOut()
        {
            var callbackUrl = Url.Action(nameof(SignedOut), "Account", values: null, protocol: Request.Scheme);
            var properties = new AuthenticationProperties { RedirectUri = callbackUrl };
            return SignOut(properties,
                CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme);
        }

        // GET: /Account/SignedOut
        [HttpGet]
        public IActionResult SignedOut()
        {
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                // Redirect to home page if the user is authenticated.
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }

            return View();
        }

        [HttpGet]
        public IActionResult SignedOutCallback()
        {
            //Local sign out
            HttpContext.SignOutAsync();
            return RedirectToAction("SignedOut", "Account");
        }

        public IActionResult ReauthenticationCallBack()
        {
            InitializeDataForRPFrame();
            ViewData["Action"] = "ReauthenticationCallBack";
            return View("RPIFrame");
        }

        public ActionResult RPIFrame()
        {
            InitializeDataForRPFrame();
            ViewData["Action"] = "RPIFrame";

            return View();
        }

        private void InitializeDataForRPFrame()
        {
            var sessionState = HttpContext.User.Claims.Where(x => x.Type == OpenIdConnectConstants.SessionState).Select(x => x.Value).FirstOrDefault();
            ViewData[OpenIdConnectConstants.ClientId] = configuration.ClientId();
            ViewData[OpenIdConnectConstants.SessionState] = sessionState;
            ViewData["OPDomain"] = configuration.IssuerDomain();
            var authorizationRequest = OpenIdConnectHelper.GenerateReauthenticateUri(HttpContext, configuration);
            ViewData["Reauthenticate"] = authorizationRequest;
        }

    }
}
