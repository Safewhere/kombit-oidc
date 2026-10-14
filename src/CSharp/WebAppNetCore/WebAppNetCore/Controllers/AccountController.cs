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
using System.Globalization;
using WebAppNetCore.Models;
using WebAppNetCore.OAuth;

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

        // POST: /Account/SignIn
        // POST with an antiforgery token protects the flow initiation against CSRF (FAPI 2.0 section 5.3.3.1 item 12).
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SignIn([FromForm] string loa, [FromForm] string max_age, [FromForm] bool forceLogin, [FromForm] bool isPassive, [FromForm] string fault)
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

            FaultInjection.Write(properties, FaultInjection.Parse(fault, configuration, FaultInjection.SignInFaults));

            try
            {
                await HttpContext.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme, properties);
            }
            catch (Exception exception) when (exception is OAuthClientException || exception is InvalidOperationException)
            {
                // For example a discovery document of another issuer, a PAR error response, or PAR required without a PAR endpoint.
                TempData[ErrorPage.MessageKey] = exception.Message;
                return RedirectToAction(nameof(HomeController.Error), "Home");
            }

            return new EmptyResult();
        }

        // POST: /Account/UserInfo
        // Calls UserInfo with the access token of the session: with the DPoP scheme and a proof for a DPoP-bound token.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> UserInfo([FromServices] UserInfoClient userInfoClient, [FromServices] ClientSessionStore sessionStore, [FromForm] string fault)
        {
            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (!result.Succeeded)
            {
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }

            var session = sessionStore.Get(result.Properties);
            try
            {
                var userInfo = await userInfoClient.GetAsync(
                    result.Properties.GetTokenValue(OpenIdConnectConstants.AccessToken),
                    result.Properties.GetTokenValue("token_type"),
                    session,
                    FaultInjection.Parse(fault, configuration, FaultInjection.UserInfoFaults),
                    HttpContext.RequestAborted);
                if (userInfo != null && session != null)
                {
                    session.LastUserInfo = ProtocolTrace.FormatJson(userInfo.Json);
                }

                TempData[ProtocolViewModel.ResultKey] = userInfo == null ? "The discovery document has no UserInfo endpoint." : "The UserInfo request succeeded.";
            }
            catch (OAuthClientException exception)
            {
                TempData[ProtocolViewModel.ResultKey] = exception.Message;
            }

            return RedirectToAction(nameof(HomeController.Index), "Home");
        }

        // POST: /Account/Refresh
        // Uses the refresh token with the DPoP key of the sign-in, and stores the new access token in the session.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Refresh([FromServices] TokenClient tokenClient, [FromServices] ClientSessionStore sessionStore, [FromForm] string fault)
        {
            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (!result.Succeeded)
            {
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }

            var refreshToken = result.Properties.GetTokenValue("refresh_token");
            if (string.IsNullOrEmpty(refreshToken))
            {
                TempData[ProtocolViewModel.ResultKey] = "The session has no refresh token. Identify issues one when the connection has AllowRefreshToken=true.";
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }

            try
            {
                var response = await tokenClient.RefreshAsync(
                    refreshToken,
                    sessionStore.Get(result.Properties),
                    FaultInjection.Parse(fault, configuration, FaultInjection.RefreshFaults),
                    HttpContext.RequestAborted);

                // The sample keeps the ID token of the sign-in, which the handler validated.
                var tokens = result.Properties.GetTokens().ToDictionary(t => t.Name, t => t.Value);
                tokens[OpenIdConnectConstants.AccessToken] = response.AccessToken;
                if (!string.IsNullOrEmpty(response.TokenType))
                {
                    tokens["token_type"] = response.TokenType;
                }

                // FAPI 2.0 asks for no routine rotation (section 5.3.2.1 item 9). When Identify returns a refresh token anyway, it
                // replaces the old one (section 5.3.3.1 item 6).
                var rotated = !string.IsNullOrEmpty(response.RefreshToken) && response.RefreshToken != refreshToken;
                if (rotated)
                {
                    tokens["refresh_token"] = response.RefreshToken;
                }

                if (int.TryParse(response.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out var expiresIn))
                {
                    tokens["expires_at"] = DateTimeOffset.UtcNow.AddSeconds(expiresIn).ToString("o", CultureInfo.InvariantCulture);
                }

                result.Properties.StoreTokens(tokens.Select(t => new AuthenticationToken { Name = t.Key, Value = t.Value }));
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, result.Principal, result.Properties);
                TempData[ProtocolViewModel.ResultKey] = rotated
                    ? "The refresh succeeded. Identify returned a new refresh token, and the sample stored it."
                    : "The refresh succeeded. The refresh token is unchanged.";
            }
            catch (OAuthClientException exception)
            {
                TempData[ProtocolViewModel.ResultKey] = exception.Message;
            }

            return RedirectToAction(nameof(HomeController.Index), "Home");
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
