using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;
using System;
using System.Threading.Tasks;
using System.Security.Claims;
using System.Linq;
using System.Collections.Generic;
using Microsoft.IdentityModel.Logging;
using System.Net.Http.Headers;
using System.Net.Http;
using System.Text.Json;
using System.Text;
using System.Security.Cryptography.X509Certificates;

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

        private static string Encode(string? data)
        {
            if (string.IsNullOrEmpty(data))
            {
                return string.Empty;
            }
            // Escape spaces as '+'.
            return Uri.EscapeDataString(data).Replace("%20", "+");
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
            connectOptions.Authority = configuration.ClaimsIssuer();
            connectOptions.GetClaimsFromUserInfoEndpoint = true;
            connectOptions.UsePkce = true;

            var responseMode = configuration.ResponseMode();
            if(string.IsNullOrEmpty(responseMode))
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
            connectOptions.ProtocolValidator.RequireNonce = configuration.RequireNonce();
            connectOptions.TokenValidationParameters.NameClaimType = ClaimTypes.NameIdentifier;
            connectOptions.BackchannelHttpHandler = HttpClientHandlerProvider.Create();

            connectOptions.Events = new OpenIdConnectEvents
            {
                OnRedirectToIdentityProvider = async (context) =>
                {
                    Console.WriteLine("OnRedirectToIdentityProvider.");
                    context.Options.AuthenticationMethod = configuration.AuthorizationEndpointMethod();
                    if (context.Properties.Parameters.TryGetValue("acr_values", out object acrValues))
                    {
                        context.ProtocolMessage.Parameters.Add("acr_values", acrValues.ToString());
                    }

                    if (context.Properties.Parameters.TryGetValue("max_age", out object max_age))
                    {
                        context.ProtocolMessage.Parameters.Add("max_age", max_age.ToString());
                    }

                    await Task.FromResult(0);
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
                    var tokenEndpoint = configuration.TokenEndpoint();

                    using var httpClient = new HttpClient();

                    var parameters = new Dictionary<string, string>
                    {
                        { "grant_type", "authorization_code" },
                        { "code", context.ProtocolMessage.Code },
                        { "redirect_uri", context.Properties.Items[OpenIdConnectDefaults.RedirectUriForCodePropertiesKey] },
                        { "session_state", context.ProtocolMessage.SessionState},
                        { "code_verifier", context.TokenEndpointRequest.Parameters["code_verifier"] }
                    };

                    var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint);

                    if (configuration.TokenAuthnMethod() == "client_secret_post")
                    {
                        parameters["client_id"] = configuration.ClientId();
                        parameters["client_secret"] = configuration.ClientSecret();
                        request.Content = new FormUrlEncodedContent(parameters);
                    }
                    else if (configuration.TokenAuthnMethod() == "client_secret_basic")
                    {
                        var creds = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Encode(configuration.ClientId())}:{Encode(configuration.ClientSecret())}"));
                        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", creds);
                        request.Content = new FormUrlEncodedContent(parameters);
                    }
                    else
                    {
                        throw new InvalidOperationException($"Unsupported TokenAuthnMethod: {configuration.TokenAuthnMethod()}");
                    }

                    var response = await httpClient.SendAsync(request);
                    response.EnsureSuccessStatusCode();

                    var responseContent = await response.Content.ReadAsStringAsync();
                    var tokenResponse = JsonDocument.Parse(responseContent).RootElement;

                    var idToken = tokenResponse.GetProperty("id_token").GetString();
                    var accessToken = tokenResponse.GetProperty("access_token").GetString();

                    // Read the Id token header to determine if it is encrypted
                    if (!string.IsNullOrEmpty(idToken))
                    {
                        var handler = new JsonWebTokenHandler();
                        var jwt = handler.ReadJsonWebToken(idToken);
                        if(OpenIdConnectHelper.IdTokenEncryptedResponseAlgs.Contains(jwt.Alg) ||
                           OpenIdConnectHelper.IdTokenEncryptedResponseEnc.Contains(jwt.Enc))
                        {
                            // Load certificate from store or file (for demo only)
                            var cert = GetDecryptionCertificate(configuration);
                            if(cert == null || !cert.HasPrivateKey)
                            {
                                throw new InvalidOperationException("Decryption certificate is not configured or does not have a private key.");
                            }
                            var encryptionCredentials = new X509EncryptingCredentials(cert, jwt.Alg, jwt.Enc);
                            idToken = OpenIdConnectHelper.DecryptToken(idToken, encryptionCredentials);

                            context.Options.TokenValidationParameters.TokenDecryptionKey = new X509SecurityKey(cert);
                            context.Options.TokenValidationParameters.CryptoProviderFactory = new IdentifyCryptoProviderFactory();
                        }
                    }

                    context.HandleCodeRedemption(accessToken, idToken);

                    await Task.FromResult(0);
                },
                OnTokenResponseReceived = async (context) =>
                {
                    Console.WriteLine("OnTokenResponseReceived.");
                    await Task.FromResult(0);
                },
                OnTokenValidated = async (context) =>
                {
                    Console.WriteLine("OnTokenValidated.");
                    await Task.FromResult(0);
                },
                OnUserInformationReceived = async (context) =>
                {
                    Console.WriteLine("OnUserInformationReceived.");
                    await Task.FromResult(0);
                },
                OnAuthenticationFailed = async (context) =>
                {
                    Console.WriteLine("OnAuthenticationFailed.");
                    await Task.FromResult(0);
                }
            };
        }

        private static X509Certificate2? GetDecryptionCertificate(IConfiguration configuration)
        {
            // Load certificate from store or file (for demo only)
            var certPath = ConfigurationExtensions.IdTokenDecryptionCertPath(configuration);
            var certPassword = ConfigurationExtensions.IdTokenDecryptionCertPassword(configuration);
            if (!string.IsNullOrEmpty(certPath) && !string.IsNullOrEmpty(certPassword))
            {
                return new X509Certificate2(certPath, certPassword);
            }

            return null;
        }
    }
}
