using System.ComponentModel;
using System.Diagnostics;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using IdentityModel.Client;
using IdentityModel.OidcClient;
using IdentityModel.OidcClient.Browser;
using Microsoft.IdentityModel.Tokens;
namespace KomitWpfOIDC
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window, INotifyPropertyChanged
    {
        private TokenInfo? _tokenInfo;
        private OidcClientOptions? _options;
        private static readonly HttpClient _http = new HttpClient();
        public MainWindow()
        {
            InitializeComponent();
            InitializeOidcClient();
            DataContext = this;
        }
        private void InitializeOidcClient()
        {
            _options = new OidcClientOptions()
            {
                Authority = ConfigurationExtensions.ClaimsIssuer,
                ClientId = ConfigurationExtensions.ClientId,
                ClientSecret = ConfigurationExtensions.ClientSecret,
                Scope = ConfigurationExtensions.Scope,
                RedirectUri = ConfigurationExtensions.LoopbackRedirect,
                PostLogoutRedirectUri = ConfigurationExtensions.LoopbackRedirect,
                Browser = new SystemBrowser(),
                Policy = new Policy
                {
                    Discovery = new DiscoveryPolicy()
                    {
                        ValidateEndpoints = false,
                        RequireHttps = true
                    }
                }
            };
        }
        private async void BtnLogin_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _tokenInfo = new TokenInfo();
                string acrValues = (AssuranceLevelCombo.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "";
                int.TryParse(MaxAgeBox.Text, out int maxAgeSec);

                // 1) Build authorize URL (authorization_code flow)
                var authorizeUrl = await OpenIdConnectHelper.GenerateReauthenticateUri(acrValues, maxAgeSec);

                // 2) Launch browser and wait for redirect
                var browser = new SystemBrowser();
                var browserResult = await browser.InvokeAsync(new BrowserOptions
                    (authorizeUrl.Url, ConfigurationExtensions.LoopbackRedirect));

                if (browserResult.ResultType != BrowserResultType.Success)
                {
                    return;
                }

                // 3) Parse returned URL to extract code and state
                var respUrl = new Uri(browserResult.Response);
                var query = respUrl.Query.TrimStart('?');
                var parsed = query.Split(new[] { '&' }, StringSplitOptions.RemoveEmptyEntries)
                                  .Select(p => p.Split('='))
                                  .Where(parts => parts.Length == 2)
                                  .ToDictionary(parts => Uri.UnescapeDataString(parts[0]), parts => Uri.UnescapeDataString(parts[1]));

                if (!parsed.TryGetValue("code", out var code))
                {
                    return;
                }

                // 4) Exchange code for tokens at token endpoint
                var tokenRequest = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string,string>("grant_type", "authorization_code"),
                    new KeyValuePair<string,string>("code", code),
                    new KeyValuePair<string,string>("redirect_uri", ConfigurationExtensions.LoopbackRedirect),
                    new KeyValuePair<string,string>("client_id", ConfigurationExtensions.ClientId),
                    new KeyValuePair<string,string>("client_secret", ConfigurationExtensions.ClientSecret),
                    new KeyValuePair<string,string>("code_verifier", authorizeUrl.CodeVerifier)
                });

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
                    return;
                }

                // 5) Validate (and decrypt if necessary) the id_token using JwtSecurityTokenHandler
                try
                {
                    string tokenToValidate = idToken!;

                    // Read header to pick algorithms if present
                    string? headerJson = OpenIdConnectHelper.GetJwtHeader(tokenToValidate);
                    string? keyMgmtAlg = null;
                    string? contentEncAlg = null;
                    bool isEncrypted = false;
                    if (!string.IsNullOrEmpty(headerJson))
                    {
                        try
                        {
                            using var hdrDoc = JsonDocument.Parse(headerJson);
                            var hdrRoot = hdrDoc.RootElement;
                            if (hdrRoot.TryGetProperty("alg", out var jalg)) keyMgmtAlg = jalg.GetString();
                            if (hdrRoot.TryGetProperty("enc", out var jenc))
                            {
                                contentEncAlg = jenc.GetString();
                                isEncrypted = !string.IsNullOrWhiteSpace(contentEncAlg);
                            }
                        }
                        catch
                        {
                            isEncrypted = false;
                        }
                    }
                    if (isEncrypted)
                    {

                        var decryptCert = OpenIdConnectHelper.GetDecryptionCertificate();
                        if (decryptCert == null)
                            throw new InvalidOperationException("Id token is encrypted but no decryption certificate is configured.");

                        var encCreds = new EncryptingCredentials(new X509SecurityKey(decryptCert), keyMgmtAlg, contentEncAlg);

                        // Use your DecryptToken helper to get inner JWS/plaintext
                        string decryptedJws;
                        try
                        {
                            decryptedJws = OpenIdConnectHelper.DecryptToken(tokenToValidate, encCreds);
                        }
                        catch (SecurityTokenDecryptionFailedException)
                        {
                            throw;
                        }

                        if (string.IsNullOrWhiteSpace(decryptedJws))
                            throw new SecurityTokenException("Decryption succeeded but no inner JWS was obtained.");

                        tokenToValidate = decryptedJws;
                        _tokenInfo.IdToken = decryptedJws;
                    }
                    else
                    {
                        _tokenInfo.IdToken = tokenToValidate;
                    }

                    // Discover OP and validate signature/claims using JWKS (same as before)
                    var disco = await _http.GetDiscoveryDocumentAsync(new IdentityModel.Client.DiscoveryDocumentRequest
                    {
                        Address = ConfigurationExtensions.ClaimsIssuer,
                        Policy = new IdentityModel.Client.DiscoveryPolicy
                        {
                            RequireHttps = true,
                            ValidateEndpoints = false
                        }
                    });
                    if (disco.IsError) throw new Exception("Discovery error: " + disco.Error);

                    var jwksJson = await _http.GetStringAsync(disco.JwksUri);
                    var jwks = new Microsoft.IdentityModel.Tokens.JsonWebKeySet(jwksJson);
                    if (jwks.Keys == null || jwks.Keys.Count == 0)
                        throw new Exception("OP JWKS is empty. Check issuer/jwks_uri on the server.");

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
                    handler.ValidateToken(tokenToValidate, tvp, out _);
                    IsAuthenticated = true;
                }
                catch (Exception ex)
                {
                    return;
                }

                _tokenInfo.AccessToken = accessToken;
                _tokenInfo.RefreshToken = refreshToken;
                _tokenInfo.AccessTokenExp = DateTimeOffset.UtcNow.AddSeconds(expiresIn);
                LogInfomation(_tokenInfo?.IdToken);

            }
            catch (Exception ex)
            {
            }
        }
        private async void BtnLogout_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (_tokenInfo is null)
                {
                    return;
                }

                var browser = new SystemBrowser();
                var wait = browser.WaitForCallbackAsync(ConfigurationExtensions.LoopbackRedirect, TimeSpan.FromSeconds(30));

                LaunchEndSessionInBrowser();
                IsAuthenticated = false;

                await wait;
                _tokenInfo.Clear();
                AssuranceLevelCombo.SelectedIndex = -1;
                MaxAgeBox.Text = string.Empty;

            }
            catch (Exception ex)
            {
            }
        }
        private async Task RevokeAsync(TokenInfo token)
        {
            if (!string.IsNullOrWhiteSpace(token.RefreshToken))
            {
                var res = await _http.RevokeTokenAsync(new TokenRevocationRequest
                {
                    Address = ConfigurationExtensions.RevokeEndpoint,
                    ClientId = ConfigurationExtensions.ClientId,
                    ClientSecret = ConfigurationExtensions.ClientSecret,
                    Token = token.RefreshToken!,
                    TokenTypeHint = "refresh_token"
                });
                if (res.IsError) Log($"Revoke refresh_token failed: {res.Error}");
            }

            if (!string.IsNullOrWhiteSpace(token.AccessToken))
            {
                var res = await _http.RevokeTokenAsync(new TokenRevocationRequest
                {
                    Address = ConfigurationExtensions.RevokeEndpoint,
                    ClientId = ConfigurationExtensions.ClientId,
                    ClientSecret = ConfigurationExtensions.ClientSecret,
                    Token = token.AccessToken!,
                    TokenTypeHint = "access_token"
                });
                if (res.IsError) Log($"Revoke access_token failed: {res.Error}");
            }
        }
        private void LaunchEndSessionInBrowser()
        {
            var postLogout = Uri.EscapeDataString(ConfigurationExtensions.LoopbackRedirect);
            var endSessionUrl = $"{ConfigurationExtensions.EndSessionEndpoint}?id_token_hint={Uri.EscapeDataString(_tokenInfo?.IdToken ?? "")}&post_logout_redirect_uri={postLogout}";
            Process.Start(new ProcessStartInfo
            {
                FileName = endSessionUrl,
                UseShellExecute = true
            });
        }
        private void Log(string s, bool flag = false)
        {
            void write()
            {
                if (!flag)
                    TxtLog.Text += (s + Environment.NewLine);
                else
                    TxtLog.Text = (s + Environment.NewLine);
            }

            if (Dispatcher.CheckAccess()) write();
            else Dispatcher.Invoke(write);
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
            var decoded = OpenIdConnectHelper.GetJwtInfor(token);
            TxtLog.Text = token;
            TxtHeader.Text = decoded.Value.HeaderJson;
            TxtPayload.Text = decoded.Value.PayloadJson;
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