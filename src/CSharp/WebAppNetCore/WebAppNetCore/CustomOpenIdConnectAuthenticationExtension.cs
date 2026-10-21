using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.WebUtilities;
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
            services.AddSingleton<DPoPNonceStore>();
            services.AddSingleton<TokenClient>();
            services.AddSingleton<UserInfoClient>();
            services.AddSingleton<PushedAuthorizationClient>();
            services.AddSingleton<TokenManagementClient>();
            services.AddMemoryCache();
            services.AddSingleton<ClientSessionStore>();

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
            // Disable (the default) keeps the direct authorization request, because the handler would otherwise push as soon as
            // discovery advertises a PAR endpoint. When the handler pushes, OnPushAuthorization sends the request.
            connectOptions.PushedAuthorizationBehavior = configuration.PushedAuthorization();
            // The browser request carries only OAuth parameters, not the x-client-SKU and x-client-ver telemetry parameters.
            // After a push, the browser may send only client_id and request_uri (FAPI 2.0 section 5.3.3.2 item 6).
            connectOptions.DisableTelemetry = true;

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
                    var services = context.HttpContext.RequestServices;
                    // Fails the sign-in early when the discovery document belongs to another issuer.
                    var metadata = await services.GetRequiredService<IdentifyMetadata>().GetAsync(context.HttpContext.RequestAborted);
                    // The handle goes into the state parameter, because the handler protects the properties after this event.
                    var session = services.GetRequiredService<ClientSessionStore>().Create(context.Properties);
                    session.SignInFault = FaultInjection.Read(context.Properties);
                    if (session.SignInFault != Fault.None)
                    {
                        session.Trace.Add("Fault injection", session.SignInFault + ": " + FaultInjection.Describe(session.SignInFault));
                    }

                    if (FaultInjection.BrowserRequestFaults.Contains(session.SignInFault) && !RedirectsAfterPush(configuration, metadata))
                    {
                        // The fault changes the redirect after the push. Without it, the browser would send a valid request, and the
                        // result would look like an accepted violation.
                        throw new OAuthClientException(
                            "The fault " + session.SignInFault + " needs AuthorizationEndpointMethod GET and a pushed authorization request. The sign-in did not start.");
                    }

                    if (session.SignInFault == Fault.ReplayParAssertionAtToken
                        && (configuration.TokenAuthnMethod() != "private_key_jwt" || !Pushes(configuration, metadata)))
                    {
                        // The fault sends the client assertion of the pushed request again. Without one, it has nothing to send.
                        throw new OAuthClientException(
                            "The fault ReplayParAssertionAtToken needs TokenAuthnMethod private_key_jwt and a pushed authorization request. The sign-in did not start.");
                    }

                    if (configuration.UsesDPoPKey())
                    {
                        // One key for each sign-in. The PAR proof, the token proofs, and the UserInfo proofs of the sign-in use it.
                        session.DPoPKey = DPoPKey.Create();
                        if (configuration.DPoPSendDPoPJkt())
                        {
                            context.ProtocolMessage.Parameters["dpop_jkt"] = session.DPoPKey.Thumbprint;
                        }
                    }

                    context.Options.AuthenticationMethod = configuration.AuthorizationEndpointMethod();
                    if (context.Properties.Parameters.TryGetValue("acr_values", out object acrValues))
                    {
                        context.ProtocolMessage.Parameters.Add("acr_values", acrValues.ToString());
                    }

                    if (context.Properties.Parameters.TryGetValue("max_age", out object max_age))
                    {
                        context.ProtocolMessage.Parameters.Add("max_age", max_age.ToString());
                    }

                    session.Trace.Add(
                        "Authorization request parameters",
                        configuration.PushedAuthorization() == PushedAuthorizationBehavior.Disable ? "Sent by the browser" : "Pushed when the handler uses PAR",
                        context.ProtocolMessage.Parameters.Select(p => ProtocolTrace.Detail(p.Key, p.Key == "state" ? "(set by the handler)" : p.Value)));
                },
                OnPushAuthorization = async (context) =>
                {
                    Console.WriteLine("OnPushAuthorization.");
                    var services = context.HttpContext.RequestServices;
                    // The sample sends the request itself, with the configured client authentication. After HandlePush, the handler
                    // sends nothing and redirects the browser with client_id and request_uri only. The event allows only one of
                    // HandlePush, SkipPush, and HandleClientAuthentication.
                    var session = services.GetRequiredService<ClientSessionStore>().Get(context.Properties);
                    var fault = session?.SignInFault ?? Fault.None;
                    if (fault == Fault.SkipPar)
                    {
                        // The browser gets the direct authorization request with all parameters.
                        context.SkipPush();
                        return;
                    }

                    var result = await services.GetRequiredService<PushedAuthorizationClient>().PushAsync(context.ProtocolMessage, session, fault, context.HttpContext.RequestAborted);
                    if (session != null)
                    {
                        session.PushedAuthorization = result;
                        session.Trace.Add("Browser authorization request", "client_id and request_uri only", new[]
                        {
                            ProtocolTrace.Detail("client_id", context.Options.ClientId),
                            ProtocolTrace.Detail("request_uri", result.RequestUri)
                        });
                    }
                    context.HandlePush(result.RequestUri);
                    if (FaultInjection.BrowserRequestFaults.Contains(fault))
                    {
                        // The handler writes the redirect after this event, so the browser request is changed when the response starts.
                        // OnRedirectToIdentityProvider has stopped the sign-in with POST, where the handler writes a form instead.
                        var response = context.HttpContext.Response;
                        var scope = string.Join(" ", context.Options.Scope);
                        var redirectUri = context.ProtocolMessage.RedirectUri;
                        response.OnStarting(() =>
                        {
                            var location = response.Headers.Location.ToString();
                            if (!string.IsNullOrEmpty(location))
                            {
                                response.Headers.Location = ChangeBrowserRequest(fault, location, scope, redirectUri);
                            }
                            return Task.CompletedTask;
                        });
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
                OnMessageReceived = async (context) =>
                {
                    Console.WriteLine("OnMessageReceived.");
                    // The check runs for every authorization response, also an error response, before the handler reads it.
                    var services = context.HttpContext.RequestServices;
                    var metadata = await services.GetRequiredService<IdentifyMetadata>().GetAsync(context.HttpContext.RequestAborted);
                    var failure = AuthorizationResponseIssuer.Validate(context.ProtocolMessage.Iss, metadata);
                    services.GetRequiredService<ClientSessionStore>().Get(context.Properties)?.Trace.Add(
                        "Authorization response",
                        failure ?? "iss check passed (RFC 9207)",
                        new[]
                        {
                            ProtocolTrace.Detail("iss", context.ProtocolMessage.Iss ?? "(none)"),
                            ProtocolTrace.Detail("authorization_response_iss_parameter_supported", metadata.AuthorizationResponseIssParameterSupported.ToString()),
                            ProtocolTrace.Detail("code", string.IsNullOrEmpty(context.ProtocolMessage.Code) ? "(none)" : "(present)"),
                            ProtocolTrace.Detail("error", context.ProtocolMessage.Error ?? "(none)"),
                            ProtocolTrace.Detail("error_description", context.ProtocolMessage.ErrorDescription ?? "(none)")
                        });
                    if (failure != null)
                    {
                        context.Fail(failure);
                    }
                },
                OnAuthorizationCodeReceived = async (context) =>
                {
                    Console.WriteLine("OnAuthorizationCodeReceived.");
                    Console.WriteLine("code = " + context.TokenEndpointRequest.Code);

                    var services = context.HttpContext.RequestServices;
                    var session = services.GetRequiredService<ClientSessionStore>().Get(context.Properties);
                    var fault = session?.SignInFault ?? Fault.None;
                    var tokenClient = services.GetRequiredService<TokenClient>();
                    if (fault == Fault.RedeemCodeAfter10Seconds || fault == Fault.RedeemCodeAfter5Seconds)
                    {
                        // Lets the code age before the redemption, for the tests of the code lifetime.
                        var delay = fault == Fault.RedeemCodeAfter10Seconds ? 10 : 5;
                        session?.Trace.Add("Fault injection", fault + ": the sample waits " + delay + " seconds before it redeems the code");
                        await Task.Delay(TimeSpan.FromSeconds(delay), context.HttpContext.RequestAborted);
                    }

                    var tokenResponse = await tokenClient.RedeemCodeAsync(
                        context.ProtocolMessage.Code,
                        context.Properties.Items[OpenIdConnectDefaults.RedirectUriForCodePropertiesKey],
                        context.TokenEndpointRequest.Parameters["code_verifier"],
                        context.ProtocolMessage.SessionState,
                        session,
                        fault,
                        context.HttpContext.RequestAborted);

                    if (fault == Fault.RedeemCodeTwice)
                    {
                        // The trace shows the response to the second redemption. The sign-in continues with the first response,
                        // unless the server revokes the tokens of the code after the second redemption (Identify does), and UserInfo then fails.
                        try
                        {
                            await tokenClient.RedeemCodeAsync(
                                context.ProtocolMessage.Code,
                                context.Properties.Items[OpenIdConnectDefaults.RedirectUriForCodePropertiesKey],
                                context.TokenEndpointRequest.Parameters["code_verifier"],
                                context.ProtocolMessage.SessionState,
                                session,
                                Fault.None,
                                context.HttpContext.RequestAborted);
                            session?.Trace.Add("Fault injection", "RedeemCodeTwice: the second redemption succeeded");
                        }
                        catch (OAuthClientException exception)
                        {
                            session?.Trace.Add("Fault injection", "RedeemCodeTwice: the second redemption failed: " + exception.Message);
                        }
                    }

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

                    var services = context.HttpContext.RequestServices;
                    var session = services.GetRequiredService<ClientSessionStore>().Get(context.Properties);
                    var userInfo = await services.GetRequiredService<UserInfoClient>().GetAsync(
                        context.TokenEndpointResponse?.AccessToken,
                        context.TokenEndpointResponse?.TokenType,
                        session,
                        Fault.None,
                        context.HttpContext.RequestAborted);
                    if (userInfo != null)
                    {
                        Console.WriteLine("UserInfo received.");
                        if (session != null)
                        {
                            session.LastUserInfo = ProtocolTrace.FormatJson(userInfo.Json);
                        }
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

        /// <summary>
        /// Whether the handler pushes the request and then redirects the browser with GET. It pushes with Require, and with
        /// UseIfAvailable when the discovery document has a PAR endpoint.
        /// </summary>
        private static bool RedirectsAfterPush(IConfiguration configuration, OpenIdConnectConfiguration metadata)
        {
            return configuration.AuthorizationEndpointMethod() == OpenIdConnectRedirectBehavior.RedirectGet && Pushes(configuration, metadata);
        }

        /// <summary>
        /// The browser request of a browser request fault: scope next to request_uri (ExtraBrowserParameter), redirect_uri
        /// /fault-redirect on the origin of the pushed redirect URI (ExtraBrowserRedirectUri), or request_uri without client_id
        /// (BrowserWithoutClientId).
        /// </summary>
        private static string ChangeBrowserRequest(Fault fault, string location, string scope, string redirectUri)
        {
            switch (fault)
            {
                case Fault.ExtraBrowserParameter:
                    return QueryHelpers.AddQueryString(location, "scope", scope);
                case Fault.ExtraBrowserRedirectUri:
                    return QueryHelpers.AddQueryString(location, "redirect_uri", new Uri(new Uri(redirectUri), "/fault-redirect").ToString());
                default:
                    var uri = new Uri(location);
                    var query = QueryHelpers.ParseQuery(uri.Query).Where(p => p.Key != "client_id").ToDictionary(p => p.Key, p => (string)p.Value);
                    return QueryHelpers.AddQueryString(uri.GetLeftPart(UriPartial.Path), query);
            }
        }

        private static bool Pushes(IConfiguration configuration, OpenIdConnectConfiguration metadata)
        {
            var pushedAuthorization = configuration.PushedAuthorization();
            return pushedAuthorization == PushedAuthorizationBehavior.Require
                || (pushedAuthorization == PushedAuthorizationBehavior.UseIfAvailable && !string.IsNullOrEmpty(metadata.PushedAuthorizationRequestEndpoint));
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
