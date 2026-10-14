using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Threading.Tasks;
using System.Security.Claims;
using System.Linq;
using System.Text.Json;
using Microsoft.IdentityModel.Logging;
using System.Security.Cryptography.X509Certificates;
using WebAppNetCore.OAuth;

namespace WebAppNetCore
{
    public static class CustomOpenIdConnectAuthenticationExtension
    {
        public static IServiceCollection ConfigureOpenIdServices(this IServiceCollection services, IConfiguration configuration)
        {
            IdentityModelEventSource.ShowPII = true;
            configuration.ValidateBuildingBlockSettings();
            services.AddAuthentication(options =>
            {
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddCookie()

            .AddOpenIdConnect(connectOptions => InitializeConnectOptions(connectOptions, configuration));

            services.AddHttpClient(IdentifyHttpClient.Name)
                .ConfigurePrimaryHttpMessageHandler(HttpClientHandlerProvider.Create);
            services.AddSingleton<IdentifyMetadata>();
            services.AddSingleton<ClientAuthentication>();
            services.AddSingleton<TokenClient>();
            services.AddSingleton<UserInfoClient>();

            return services;
        }

        private static void InitializeConnectOptions(OpenIdConnectOptions connectOptions, IConfiguration configuration)
        {
            connectOptions.ClientId = configuration.ClientId();
            connectOptions.ClientSecret = configuration.ClientSecret();
            connectOptions.ResponseType = configuration.ResponseType();
            connectOptions.UseTokenLifetime = true;
            connectOptions.SaveTokens = true;
            connectOptions.ClaimsIssuer = configuration.ClaimsIssuer();
            connectOptions.Authority = configuration.ClaimsIssuer();
            // The sample calls UserInfo itself in OnTokenValidated, because the handler always uses the Bearer scheme.
            connectOptions.GetClaimsFromUserInfoEndpoint = false;
            connectOptions.UsePkce = true;
            // Preserve direct GET/POST authorization and the sample's custom client authentication.
            // PAR is enabled automatically by newer middleware when advertised by discovery.
            connectOptions.PushedAuthorizationBehavior = PushedAuthorizationBehavior.Disable;

            var responseMode = configuration.ResponseMode();
            if (string.IsNullOrEmpty(responseMode))
            {
                connectOptions.ResponseMode = null;
            }
            else
            {
                connectOptions.ResponseMode = responseMode;
            }

            connectOptions.AuthenticationMethod = configuration.AuthorizationEndpointMethod();
            var scopes = configuration.Scope()
                .Split(new char[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries);
            connectOptions.Scope.Clear();
            foreach (var scope in scopes)
            {
                connectOptions.Scope.Add(scope);
            }

            connectOptions.TokenValidationParameters.ValidateAudience = true;   // by default, when we don't explicitly set ValidAudience, it is set to ClientId
            connectOptions.TokenValidationParameters.ValidateIssuer = true;
            connectOptions.TokenValidationParameters.ValidIssuer = configuration.ClaimsIssuer();
            connectOptions.ProtocolValidator = new ShortNonceProtocolValidator { RequireNonce = configuration.RequireNonce() };
            var validIdTokenSigningAlgorithms = configuration.ValidIdTokenSigningAlgorithms();
            if (validIdTokenSigningAlgorithms.Length > 0)
            {
                connectOptions.TokenValidationParameters.ValidAlgorithms = validIdTokenSigningAlgorithms;
            }
            connectOptions.TokenValidationParameters.NameClaimType = ClaimTypes.NameIdentifier;
            connectOptions.BackchannelHttpHandler = HttpClientHandlerProvider.Create();

            connectOptions.Events = new OpenIdConnectEvents
            {
                OnRedirectToIdentityProvider = async (context) =>
                {
                    Console.WriteLine("OnRedirectToIdentityProvider.");
                    // Fails the sign-in early when the discovery document belongs to another issuer.
                    await context.HttpContext.RequestServices.GetRequiredService<IdentifyMetadata>().GetAsync(context.HttpContext.RequestAborted);

                    context.Options.AuthenticationMethod = configuration.AuthorizationEndpointMethod();
                    if (context.Properties.Parameters.TryGetValue("acr_values", out object acrValues))
                    {
                        context.ProtocolMessage.Parameters.Add("acr_values", acrValues.ToString());
                    }

                    if (context.Properties.Parameters.TryGetValue("max_age", out object max_age))
                    {
                        context.ProtocolMessage.Parameters.Add("max_age", max_age.ToString());
                    }
                },
                OnRedirectToIdentityProviderForSignOut = async (context) =>
                {
                    Console.WriteLine("OnRedirectToIdentityProviderForSignOut.");
                    //Hack: POST Authentication Method is used for Logout in the OpenIdConnectHanler, it is not a thing of our demo (we have a separate button to POST logout)
                    context.Options.AuthenticationMethod = OpenIdConnectRedirectBehavior.RedirectGet;
                    context.ProtocolMessage.PostLogoutRedirectUri = context.Properties.RedirectUri;
                    await Task.FromResult(0);
                },
                OnAuthorizationCodeReceived = async (context) =>
                {
                    Console.WriteLine("OnAuthorizationCodeReceived.");
                    Console.WriteLine("code = " + context.TokenEndpointRequest.Code);

                    var tokenResponse = await context.HttpContext.RequestServices.GetRequiredService<TokenClient>().RedeemCodeAsync(
                        context.ProtocolMessage.Code,
                        context.Properties.Items[OpenIdConnectDefaults.RedirectUriForCodePropertiesKey],
                        context.TokenEndpointRequest.Parameters["code_verifier"],
                        context.ProtocolMessage.SessionState,
                        context.HttpContext.RequestAborted);

                    // Read the Id token header to determine if it is encrypted
                    var idToken = tokenResponse.IdToken;
                    if (!string.IsNullOrEmpty(idToken))
                    {
                        var handler = new JsonWebTokenHandler();
                        var jwt = handler.ReadJsonWebToken(idToken);
                        if (OpenIdConnectHelper.IdTokenEncryptedResponseAlgs.Contains(jwt.Alg) ||
                           OpenIdConnectHelper.IdTokenEncryptedResponseEnc.Contains(jwt.Enc))
                        {
                            // Load certificate from store or file (for demo only)
                            var cert = GetDecryptionCertificate(configuration);
                            if (cert == null || !cert.HasPrivateKey)
                            {
                                throw new InvalidOperationException("Decryption certificate is not configured or does not have a private key.");
                            }
                            var encryptionCredentials = new X509EncryptingCredentials(cert, jwt.Alg, jwt.Enc);
                            idToken = OpenIdConnectHelper.DecryptToken(idToken, encryptionCredentials);

                            context.Options.TokenValidationParameters.TokenDecryptionKey = new X509SecurityKey(cert);
                            context.Options.TokenValidationParameters.CryptoProviderFactory = new IdentifyCryptoProviderFactory();
                        }

                        // extract id token and save the sid claim
                        var sidClaim = handler.ReadJsonWebToken(idToken).Claims.FirstOrDefault(c => c.Type == OpenIdConnectConstants.SessionId);
                        if (sidClaim != null)
                        {
                            OpenIdConnectHelper.LiveSessions[sidClaim.Value] = true;
                        }
                    }

                    // The handler validates and saves the tokens of this response: access_token, id_token, refresh_token, token_type, and expires_at.
                    tokenResponse.IdToken = idToken;
                    context.HandleCodeRedemption(tokenResponse);
                },
                OnTokenValidated = async (context) =>
                {
                    Console.WriteLine("OnTokenValidated.");
                    // The handler skips this validation when the application redeems the code, so the sample does it here.
                    // It checks the nonce of the ID token against the nonce cookie of this browser, and at_hash when present.
                    context.Options.ProtocolValidator.ValidateTokenResponse(new OpenIdConnectProtocolValidationContext
                    {
                        ClientId = context.Options.ClientId,
                        ProtocolMessage = context.TokenEndpointResponse,
                        ValidatedIdToken = context.SecurityToken,
                        Nonce = context.Nonce
                    });

                    var identity = (ClaimsIdentity)context.Principal.Identity;

                    // Note that when "Session management" is disabled, there is no "session_state" in the token response
                    var sessionState = context.TokenEndpointResponse?.SessionState;
                    if (!string.IsNullOrEmpty(sessionState) && !identity.Claims.Any(c => c.Type == OpenIdConnectConstants.SessionState))
                    {
                        identity.AddClaim(new Claim(OpenIdConnectConstants.SessionState, sessionState));
                    }

                    var userInfo = await context.HttpContext.RequestServices.GetRequiredService<UserInfoClient>().GetAsync(
                        context.TokenEndpointResponse?.AccessToken, context.HttpContext.RequestAborted);
                    if (userInfo != null)
                    {
                        Console.WriteLine("UserInfo received.");
                        // The same processing as the handler does with GetClaimsFromUserInfoEndpoint: the sub check and the claim actions.
                        context.Options.ProtocolValidator.ValidateUserInfoResponse(new OpenIdConnectProtocolValidationContext
                        {
                            UserInfoEndpointResponse = userInfo.RawResponse,
                            ValidatedIdToken = context.SecurityToken
                        });
                        using var claims = JsonDocument.Parse(userInfo.Json);
                        foreach (var action in context.Options.ClaimActions)
                        {
                            action.Run(claims.RootElement, identity, context.Options.ClaimsIssuer ?? context.Scheme.Name);
                        }
                    }
                },
                OnAuthenticationFailed = async (context) =>
                {
                    Console.WriteLine("OnAuthenticationFailed.");
                    await Task.FromResult(0);
                },
                OnRemoteFailure = (context) =>
                {
                    Console.WriteLine("OnRemoteFailure.");
                    ErrorPage.Redirect(context.HttpContext, ErrorPage.Describe(context.Failure));
                    context.HandleResponse();
                    return Task.CompletedTask;
                }
            };
        }

        private static X509Certificate2 GetDecryptionCertificate(IConfiguration configuration)
        {
            // Load certificate from store or file (for demo only)
            var certPath = ConfigurationExtensions.IdTokenDecryptionCertPath(configuration);
            var certPassword = ConfigurationExtensions.IdTokenDecryptionCertPassword(configuration);
            if (!string.IsNullOrEmpty(certPath) && !string.IsNullOrEmpty(certPassword))
            {
                return X509CertificateLoader.LoadPkcs12FromFile(certPath, certPassword);
            }

            return null;
        }
    }
}
