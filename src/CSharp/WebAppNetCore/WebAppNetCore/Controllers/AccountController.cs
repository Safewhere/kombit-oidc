using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
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
        public IActionResult SignIn([FromQuery] string loa, [FromQuery] string max_age, [FromQuery] bool forceLogin, [FromQuery] bool isPassive)
        {
            var properties = new AuthenticationProperties { RedirectUri = "/" };
            if(!string.IsNullOrEmpty(loa))
                properties.SetParameter("acr_values", loa);
            if (!string.IsNullOrEmpty(max_age))
                properties.SetParameter("max_age", max_age);

            if (forceLogin)
                properties.SetParameter("prompt", "login");
            else if(isPassive)
                properties.SetParameter("prompt", "none");

            return Challenge(properties, OpenIdConnectDefaults.AuthenticationScheme);
        }

        // GET: /Account/SignOut
        [HttpGet]
        public IActionResult SignOut()
        {
            var callbackUrl = Url.Action(nameof(SignedOutCallback), "Account", values: null, protocol: Request.Scheme);
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

        // GET: /Account/FrontChannelLogout
        [HttpGet]
        [Route("front-channel-logout")]
        [AllowAnonymous]
        public async Task<IActionResult> FrontChannelLogout([FromQuery] string sid, [FromQuery] string iss)
        {
            // Validate issuer
            var expectedIssuer = configuration["OpenIdConnectOptions:ClaimsIssuer"];
            if (!string.Equals(iss, expectedIssuer, StringComparison.OrdinalIgnoreCase))
                return Content("<html><body>Invalid issuer.</body></html>", "text/html");

            // Normalize sid values for comparison
            string NormalizeSid(string s) => s?.Replace(' ', '+');
            var userSid = NormalizeSid(User.FindFirst("sid")?.Value);
            var incomingSid = NormalizeSid(sid);

            if (string.IsNullOrEmpty(userSid) || !string.Equals(incomingSid, userSid, StringComparison.Ordinal))
                return Content("<html><body>Invalid session.</body></html>", "text/html");

            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            Response.Headers.Remove("X-Frame-Options");
            return Content("<html><body>Logout successful.</body></html>", "text/html");
        }

        [HttpPost]
        [Route("back-channel-logout")]
        [AllowAnonymous]
        public async Task<IActionResult> BackChannelLogout([FromForm] string logout_token)
        {
            // Validate issuer
            var expectedIssuer = configuration["OpenIdConnectOptions:ClaimsIssuer"];

            if (string.IsNullOrEmpty(logout_token))
            {
                return BadRequest("Logout token is required.");
            }

            // Read the logout token and validate it
            var tokenHandler = new JwtSecurityTokenHandler();
            if (!tokenHandler.CanReadToken(logout_token))
            {
                return BadRequest("Invalid logout token format.");
            }

            JwtSecurityToken jtw = tokenHandler.ReadJwtToken(logout_token);
            
            // Logout token validation
            /*
            Validate the Logout Token signature in the same way that an ID Token signature is validated, with the following refinements.
            Validate the alg (algorithm) Header Parameter in the same way it is validated for ID Tokens. Like ID Tokens, selection of the algorithm used is governed by the id_token_signing_alg_values_supported Discovery parameter and the id_token_signed_response_alg Registration parameter when they are used; otherwise, the value SHOULD be the default of RS256. Additionally, an alg with the value none MUST NOT be used for Logout Tokens.
            Validate the iss, aud, iat, and exp Claims in the same way they are validated in ID Tokens.
            Verify that the Logout Token contains a sub Claim, a sid Claim, or both.
            Verify that the Logout Token contains an events Claim whose value is JSON object containing the member name http://schemas.openid.net/event/backchannel-logout.
            Verify that the Logout Token does not contain a nonce Claim.
            Optionally verify that another Logout Token with the same jti value has not been recently received.
            Optionally verify that the iss Logout Token Claim matches the iss Claim in an ID Token issued for the current session or a recent session of this RP with the OP.
            Optionally verify that any sub Logout Token Claim matches the sub Claim in an ID Token issued for the current session or a recent session of this RP with the OP.
            Optionally verify that any sid Logout Token Claim matches the sid Claim in an ID Token issued for the current session or a recent session of this RP with the OP. 
            */

            // Invalidate session data
            var sid = jtw.Claims.FirstOrDefault(c => c.Type == OpenIdConnectConstants.SessionId)?.Value;
            if (OpenIdConnectHelper.LiveSessions.ContainsKey(sid))
            {
                OpenIdConnectHelper.LiveSessions[sid] = false;
            }

            return Ok();
        }
    }
}
