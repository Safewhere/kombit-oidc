using System.ComponentModel;
using System.Diagnostics;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using IdentityModel.Client;
using IdentityModel.OidcClient;
using IdentityModel.OidcClient.Browser;
using Serilog;

namespace KombitWpfOIDC
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window, INotifyPropertyChanged
    {
        private TokenInfo? _tokenInfo;
        private OidcClientOptions? _options;
        private static readonly HttpClient _http = new HttpClient();
        private ClaimsPrincipal? _user;

        public MainWindow()
        {
            InitializeComponent();
            InitializeOidcClient();
            DataContext = this;
            this.Closing += MainWindow_Closing;
        }

        private void InitializeOidcClient()
        {
            _options = new OidcClientOptions()
            {
                Authority = ConfigurationExtensions.ClaimsIssuer,
                ClientId = ConfigurationExtensions.ClientId,
                Scope = ConfigurationExtensions.Scope,
                RedirectUri = ConfigurationExtensions.LoopbackRedirect,
                PostLogoutRedirectUri = ConfigurationExtensions.LoopbackRedirect,
                Browser = ConfigurationExtensions.UseCustomScheme ? new CustomSchemeBrowser(ConfigurationExtensions.CustomScheme) : new SystemBrowser(),
                Policy = new Policy
                {
                    Discovery = new DiscoveryPolicy()
                    {
                        ValidateEndpoints = false,
                        RequireHttps = true
                    }
                }
            };

            LoggerConfig.InfoAsJson("OIDC client options configured", _options);
        }

        private async void BtnLogin_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                await DoLogin(false, false);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Login failed");
            }
        }

        private async void ReAuth(object sender, RoutedEventArgs e)
        {
            Log.Information("Re-authentication requested");
            await DoLogin(false, false);
        }

        private async void ForceAuth(object sender, RoutedEventArgs e)
        {
            Log.Information("Force authentication requested");
            await DoLogin(true, false);
        }

        private async void PassiveAuth(object sender, RoutedEventArgs e)
        {
            Log.Information("Passive authentication requested");
            await DoLogin(false, true);
        }

        private async Task DoLogin(bool forceLogin, bool isPassive)
        {
            _tokenInfo = new TokenInfo();
            string acrValues = (AssuranceLevelCombo.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "";
            int.TryParse(MaxAgeBox.Text, out int maxAgeSec);

            // Build authorize URL (authorization_code flow)
            var authorizeUrl = await OpenIdConnectHelper.GenerateReauthenticateUri(acrValues, maxAgeSec, forceLogin, isPassive);

            IBrowser? browser = null;
            try
            {
                browser = ConfigurationExtensions.UseCustomScheme ? new CustomSchemeBrowser(ConfigurationExtensions.CustomScheme) : new SystemBrowser();
                var browserResult = await browser.InvokeAsync(new BrowserOptions(authorizeUrl.Url, ConfigurationExtensions.LoopbackRedirect));

                if (browserResult.ResultType != BrowserResultType.Success)
                {
                    return;
                }

                var respUrl = new Uri(browserResult.Response);
                Log.Information("Parsing response URL: {Url}", respUrl);

                var query = respUrl.Query.TrimStart('?');
                var parsed = query.Split(new[] { '&' }, StringSplitOptions.RemoveEmptyEntries).Select(p => p.Split('=')).Where(parts => parts.Length == 2)
                 .ToDictionary(parts => Uri.UnescapeDataString(parts[0]), parts => Uri.UnescapeDataString(parts[1]));

                // Validate state parameter
                if (parsed.TryGetValue("state", out var returnedState))
                {
                    if (returnedState != authorizeUrl.State)
                    {
                        Log.Error("State mismatch! Expected: {Expected}, Received: {Received}", authorizeUrl.State, returnedState);
                        return;
                    }
                }

                // Check for authorization code
                if (!parsed.TryGetValue("code", out var code))
                {
                    // Check for error
                    if (parsed.TryGetValue("error", out var error))
                    {
                        var errorDesc = parsed.TryGetValue("error_description", out var desc) ? desc : "No description";
                        Log.Error("Authorization error: {Error} - {Description}", error, errorDesc);
                    }
                    return;
                }

                // Exchange code for tokens at token endpoint
                var tokenRequestParams = new Dictionary<string, string>
                {
                    ["grant_type"] = "authorization_code",
                    ["code"] = code,
                    ["redirect_uri"] = ConfigurationExtensions.LoopbackRedirect,
                    ["client_id"] = ConfigurationExtensions.ClientId,
                    ["code_verifier"] = authorizeUrl.CodeVerifier
                };

                var tokenRequest = new FormUrlEncodedContent(tokenRequestParams);
                var tokenResp = await _http.PostAsync(ConfigurationExtensions.TokenEndpoint, tokenRequest);
                var tokenRespContent = await tokenResp.Content.ReadAsStringAsync();

                if (!tokenResp.IsSuccessStatusCode)
                {
                    return;
                }

                using var doc = JsonDocument.Parse(tokenRespContent);
                var root = doc.RootElement;
                string? idToken = root.TryGetProperty("id_token", out var jId) ? jId.GetString() : null;
                string? accessToken = root.TryGetProperty("access_token", out var jAt) ? jAt.GetString() : null;
                string? refreshToken = root.TryGetProperty("refresh_token", out var jRt) ? jRt.GetString() : null;
                int expiresIn = root.TryGetProperty("expires_in", out var jExp) && jExp.TryGetInt32(out var ei) ? ei : 3600;

                if (string.IsNullOrWhiteSpace(idToken))
                {
                    Log.Error("Token response missing id_token");
                    return;
                }

                // Validate the id_token using JwtSecurityTokenHandler
                try
                {
                    _tokenInfo.IdToken = idToken;

                    var disco = await _http.GetDiscoveryDocumentAsync(new IdentityModel.Client.DiscoveryDocumentRequest
                    {
                        Address = ConfigurationExtensions.ClaimsIssuer,
                        Policy = new IdentityModel.Client.DiscoveryPolicy
                        {
                            RequireHttps = true,
                            ValidateEndpoints = false
                        }
                    });

                    if (disco.IsError)
                    {
                        Log.Error("Discovery error: {Error}", disco.Error);
                        throw new Exception("Discovery error: " + disco.Error);
                    }

                    var jwksJson = await _http.GetStringAsync(disco.JwksUri);
                    var jwks = new Microsoft.IdentityModel.Tokens.JsonWebKeySet(jwksJson);

                    if (jwks.Keys == null || jwks.Keys.Count == 0)
                    {
                        Log.Error("OP JWKS is empty");
                        throw new Exception("OP JWKS is empty. Check issuer/jwks_uri on the server.");
                    }

                    var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
                    var tvp = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                    {
                        ValidIssuer = disco.Issuer,
                        ValidAudience = ConfigurationExtensions.ClientId,
                        IssuerSigningKeys = jwks.Keys,
                        RequireSignedTokens = true,
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        ClockSkew = TimeSpan.FromMinutes(2)
                    };
                    var principal = handler.ValidateToken(idToken, tvp, out _);
                    IsAuthenticated = true;
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "ID token validation failed");
                    return;
                }

                _tokenInfo.AccessToken = accessToken;
                _tokenInfo.RefreshToken = refreshToken;
                _tokenInfo.AccessTokenExp = DateTimeOffset.UtcNow.AddSeconds(expiresIn);
                ActivateButton(BtnIDToken);
                LogInfomation(_tokenInfo?.IdToken);
                LoggerConfig.InfoAsJson("Token Information", _tokenInfo);
            }
            finally
            {
                if (browser is IDisposable disposableBrowser)
                {
                    disposableBrowser.Dispose();
                    Log.Information("Browser instance disposed");
                }
            }
        }

        private void MainWindow_Closing(object? sender, CancelEventArgs e)
        {
            try
            {
                DoLogout();
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Logout failed");
            }
        }

        private async void BtnLogout_Click(object sender, RoutedEventArgs e)
        {
            DoLogout();
        }

        private void LaunchEndSessionInBrowser()
        {
            try
            {
                var postLogout = Uri.EscapeDataString(ConfigurationExtensions.LoopbackRedirect);
                var endSessionUrl = $"{ConfigurationExtensions.EndSessionEndpoint}?id_token_hint={Uri.EscapeDataString(_tokenInfo?.IdToken ?? "")}&post_logout_redirect_uri={postLogout}";
                Log.Debug("Launching end-session URL: {Url}", endSessionUrl);
                Process.Start(new ProcessStartInfo
                {
                    FileName = endSessionUrl,
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to launch end session URL");
            }
        }

        private async void DoLogout()
        {
            try
            {
                if (_tokenInfo is null || string.IsNullOrEmpty(_tokenInfo.IdToken))
                {
                    IsAuthenticated = false;
                    _tokenInfo = new TokenInfo();
                    AssuranceLevelCombo.SelectedIndex = -1;
                    MaxAgeBox.Text = string.Empty;
                    return;
                }

                // For custom scheme, we need different handling
                if (ConfigurationExtensions.UseCustomScheme)
                {
                    // Build end session URL
                    var endSessionUrl = $"{ConfigurationExtensions.EndSessionEndpoint}?" +
                        $"id_token_hint={Uri.EscapeDataString(_tokenInfo.IdToken)}&" +
                    $"post_logout_redirect_uri={Uri.EscapeDataString(ConfigurationExtensions.LoopbackRedirect)}";

                    Log.Information("End session URL: {Url}", endSessionUrl);

                    // Launch browser for logout
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = endSessionUrl,
                        UseShellExecute = true
                    });

                    IsAuthenticated = false;
                    _tokenInfo.Clear();
                    AssuranceLevelCombo.SelectedIndex = -1;
                    MaxAgeBox.Text = string.Empty;
                }
                else
                {
                    // SystemBrowser (loopback) - wait for callback
                    var browser = new SystemBrowser();
                    var wait = browser.WaitForCallbackAsync(ConfigurationExtensions.LoopbackRedirect, TimeSpan.FromSeconds(30));
                    LaunchEndSessionInBrowser();
                    IsAuthenticated = false;
                    await wait;
                    _tokenInfo.Clear();
                    AssuranceLevelCombo.SelectedIndex = -1;
                    MaxAgeBox.Text = string.Empty;
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error during logout");
                IsAuthenticated = false;
                if (_tokenInfo != null)
                {
                    _tokenInfo.Clear();
                }
                AssuranceLevelCombo.SelectedIndex = -1;
                MaxAgeBox.Text = string.Empty;
            }
        }

        private void ResetMenuButtons()
        {
            BtnIDToken.Style = (Style)FindResource("menuButton");
            BtnAccessToken.Style = (Style)FindResource("menuButton");
        }

        private void ActivateButton(Button btn)
        {
            ResetMenuButtons();
            btn.Style = (Style)FindResource("menuButtonActive");
        }

        private void ShowIDToken(object sender, RoutedEventArgs e)
        {
            ActivateButton(BtnIDToken);
            LogInfomation(_tokenInfo?.IdToken);
        }

        private void ShowAccessToken(object sender, RoutedEventArgs e)
        {
            ActivateButton(BtnAccessToken);
            LogInfomation(_tokenInfo?.AccessToken);
        }

        private void LogInfomation(string? token)
        {
            if (!string.IsNullOrEmpty(token))
            {
                var decoded = OpenIdConnectHelper.GetJwtInfor(token);
                TxtLog.Text = token;
                TxtHeader.Text = decoded.Value.HeaderJson;
                TxtPayload.Text = decoded.Value.PayloadJson;
            }
        }

        private bool _isAuthenticated;
        public bool IsAuthenticated
        {
            get => _isAuthenticated;
            set { _isAuthenticated = value; OnPropertyChanged(); }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged([CallerMemberName] string? name = null)
       => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}