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
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

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
            var tokenHandler = new JsonWebTokenHandler();
            if (!tokenHandler.CanReadToken(logout_token))
            {
                return BadRequest("Invalid logout token format.");
            }

            // Read the token header to check if it's encrypted
            var token = tokenHandler.ReadJsonWebToken(logout_token);
            string decryptedTokenString = logout_token;
            
            // Check if the token is encrypted (JWE)
            if (OpenIdConnectHelper.IdTokenEncryptedResponseAlgs.Contains(token.Alg) ||
                OpenIdConnectHelper.IdTokenEncryptedResponseEnc.Contains(token.Enc))
            {
                // Token is encrypted, decrypt it
                var certPath = configuration.IdTokenDecryptionCertPath();
                var certPassword = configuration.IdTokenDecryptionCertPassword();
                
                if (string.IsNullOrEmpty(certPath) || string.IsNullOrEmpty(certPassword))
                {
                    return BadRequest("Decryption certificate is not configured.");
                }
                
                var cert = new X509Certificate2(certPath, certPassword);
                if (cert == null || !cert.HasPrivateKey)
                {
                    return BadRequest("Decryption certificate does not have a private key.");
                }
                
                var encryptionCredentials = new X509EncryptingCredentials(cert, token.Alg, token.Enc);
                decryptedTokenString = OpenIdConnectHelper.DecryptToken(logout_token, encryptionCredentials);
            }

            // Now read the decrypted token
            JwtSecurityToken jwt = new JwtSecurityTokenHandler().ReadJwtToken(decryptedTokenString);

            // Logout token validation
            /*
            For demo purposes, we ignore the logout token validation.
            */

            // Invalidate session data, so next request with this session id will be rejected
            var sid = jwt.Claims.FirstOrDefault(c => c.Type == OpenIdConnectConstants.SessionId)?.Value;
            if (!string.IsNullOrEmpty(sid) && OpenIdConnectHelper.LiveSessions.ContainsKey(sid))
            {
                OpenIdConnectHelper.LiveSessions[sid] = false;
            }

            return Ok();
        }
    }
}
