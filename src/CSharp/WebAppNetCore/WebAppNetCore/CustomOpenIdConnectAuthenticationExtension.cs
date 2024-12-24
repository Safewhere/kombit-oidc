using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Threading.Tasks;
using System.Security.Claims;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Logging;

namespace WebAppNetCore
{
    public static class CustomOpenIdConnectAuthenticationExtension
    {
        public static IServiceCollection ConfigureOpenIdServices(this IServiceCollection services, IConfiguration configuration)
        {
            IdentityModelEventSource.ShowPII = true;
            services.AddAuthentication(options =>
            {
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddCookie()

            .AddOpenIdConnect(connectOptions => InitializeConnectOptions(connectOptions, configuration));

            return services;
        }

        private static void InitializeConnectOptions(OpenIdConnectOptions connectOptions, IConfiguration configuration)
        {
            string accessToken = string.Empty;
            string sessionState = string.Empty;
            string idToken = string.Empty;

            connectOptions.ClientId = configuration.ClientId();
            connectOptions.ClientSecret = configuration.ClientSecret();
            connectOptions.ResponseType = configuration.ResponseType();
            connectOptions.UseTokenLifetime = true;
            connectOptions.SaveTokens = true;
            connectOptions.ClaimsIssuer = configuration.ClaimsIssuer();
            connectOptions.GetClaimsFromUserInfoEndpoint = true;
            connectOptions.UsePkce = configuration.UsePKCE();

            var responseMode = configuration.ResponseMode();
            if(string.IsNullOrEmpty(responseMode))
            {
                connectOptions.ResponseMode = null;
            }
            else
            {
                connectOptions.ResponseMode = responseMode;
            }

            connectOptions.Configuration = new OpenIdConnectConfiguration()
            {
                AuthorizationEndpoint = configuration.AuthorizationEndpoint(),
                TokenEndpoint = configuration.TokenEndpoint(),
                UserInfoEndpoint = configuration.UserInfoEndpoint(),
                EndSessionEndpoint = configuration.EndSessionEndpoint(),
                
                HttpLogoutSupported = true,

            };
            connectOptions.Events = new OpenIdConnectEvents
            {
                OnAuthorizationCodeReceived = async (context) =>
                {
                    Console.WriteLine("OnAuthorizationCodeReceived.");
                    Console.WriteLine("code = " + context.TokenEndpointRequest.Code);
                    await Task.FromResult(0);
                },
                OnTokenResponseReceived = async (context) =>
                {
                    Console.WriteLine("OnTokenResponseReceived.");
                    Console.WriteLine("IdToken = " + context.TokenEndpointResponse.IdToken);
                    Console.WriteLine("Token = " + context.TokenEndpointResponse.AccessToken);
                    Console.WriteLine("OnTokenResponseReceived.");
                    accessToken = context.TokenEndpointResponse.AccessToken;
                    idToken = context.TokenEndpointResponse.IdToken;
                    sessionState = context.TokenEndpointResponse.SessionState;
                    await Task.FromResult(0);
                },
                OnRemoteFailure = async (context) =>
                {
                    context.HttpContext.Items.Add("RemoteError", context.Failure.ToString());
                    Console.WriteLine("OnRemoteFailure.");
                    Console.WriteLine(context.Failure.ToString());

                    await Task.FromResult(0);
                },
                OnMessageReceived = async (context) =>
                {
                    await Task.FromResult(0);
                },
                OnTicketReceived = async (context) =>
                {
                    Console.WriteLine("ConTicketReceived");
                    await Task.FromResult(0);
                },
                OnUserInformationReceived = async (context) =>
                {
                    await Task.FromResult(0);
                },
                OnTokenValidated = async (context) =>
                {
                    Console.WriteLine("OnTokenValidated.");
                    Console.WriteLine(context.SecurityToken.ToString());
                    if (accessToken != null)
                    {
                        //var token = new JwtSecurityToken(accessToken);
                        ClaimsIdentity identity = context.Principal.Identity as ClaimsIdentity;
                        if (identity != null)
                        {
                            Claim sessionStateClaim = null;
                            if (!string.IsNullOrEmpty(sessionState))
                            {
                                sessionStateClaim = new Claim(OpenIdConnectConstants.SessionState, sessionState);
                            }
                            if (!identity.Claims.Any(c => c.Type == OpenIdConnectConstants.SessionState) && sessionStateClaim != null)
                            {
                                identity.AddClaim(sessionStateClaim);
                            }
                            identity.AddClaim(new Claim(OpenIdConnectConstants.IdToken, idToken));
                        }
                    }
                    await Task.FromResult(0);
                }
            };

            var scopes = configuration.Scope()
                .Split(new char[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries);
            connectOptions.Scope.Clear();
            foreach (var scope in scopes)
            {
                connectOptions.Scope.Add(scope);
            }

            var signingKey = configuration.IssuerSigningKey();
            connectOptions.TokenValidationParameters.IssuerSigningKeys = new List<SecurityKey> {
                new RsaSecurityKey(signingKey.GetRSAPublicKey().ExportParameters(false)),
                new X509SecurityKey(signingKey)
            };
            connectOptions.TokenValidationParameters.ValidateAudience = true;   // by default, when we don't explicitly set ValidAudience, it is set to ClientId
            connectOptions.TokenValidationParameters.ValidateIssuer = true;
            connectOptions.TokenValidationParameters.ValidIssuer = configuration.ClaimsIssuer();
            connectOptions.ProtocolValidator.RequireNonce = configuration.RequireNonce();
            connectOptions.TokenValidationParameters.NameClaimType = ClaimTypes.NameIdentifier;
            connectOptions.BackchannelHttpHandler = HttpClientHandlerProvider.Create();
        }
    }
}
