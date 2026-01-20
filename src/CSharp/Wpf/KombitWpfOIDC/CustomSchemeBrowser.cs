using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Web;
using IdentityModel.OidcClient.Browser;
using Serilog;

namespace KombitWpfOIDC
{
    /// <summary>
    /// Browser implementation that uses custom URL scheme (wpfoidc://callback) 
    /// instead of HTTP loopback for OAuth callbacks
    /// </summary>
    public class CustomSchemeBrowser : IBrowser
    {
        private const string CustomScheme = "wpfoidc";
        private readonly SemaphoreSlim _semaphore = new SemaphoreSlim(0, 1);
        private BrowserResult? _result;
        private readonly EventHandler<string> _callbackHandler;
        private bool _disposed = false;

        public CustomSchemeBrowser()
        {
            // Ensure the custom scheme is registered on first use
            CustomSchemeProtocolHandler.RegisterScheme();

            // Create instance-specific callback handler
            _callbackHandler = OnCallbackReceived;

            // Subscribe to callback handlers
            CustomSchemeProtocolHandler.CallbackReceived += _callbackHandler;
            IpcCallbackHandler.CallbackReceived += _callbackHandler;
        }

        public async Task<BrowserResult> InvokeAsync(BrowserOptions options, CancellationToken cancellationToken = default)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(CustomSchemeBrowser));
            }

            try
            {
                // Reset result for this invocation
                _result = null;

                Process.Start(new ProcessStartInfo
                {
                    FileName = options.StartUrl,
                    UseShellExecute = true
                });

                // Wait for the callback or timeout
                var timeout = TimeSpan.FromMinutes(5);
                var completed = await _semaphore.WaitAsync(timeout, cancellationToken);

                if (!completed)
                {
                    return new BrowserResult
                    {
                        ResultType = BrowserResultType.Timeout,
                        Error = "Timeout waiting for callback."
                    };
                }

                if (_result != null)
                {
                    var result = _result;
                    _result = null; // Clear for next use
                    return result;
                }

                return new BrowserResult
                {
                    ResultType = BrowserResultType.UnknownError,
                    Error = "No result received"
                };
            }
            catch (Exception ex)
            {
                return new BrowserResult
                {
                    ResultType = BrowserResultType.UnknownError,
                    Error = ex.ToString()
                };
            }
        }

        private void OnCallbackReceived(object? sender, string callbackUrl)
        {
            if (_disposed)
            {
                return;
            }

            try
            {
                // Parse the callback URL
                var uri = new Uri(callbackUrl);

                // Check if there's an error in the callback
                var query = HttpUtility.ParseQueryString(uri.Query);
                var error = query["error"];
                var errorDescription = query["error_description"];

                if (!string.IsNullOrEmpty(error))
                {
                    _result = new BrowserResult
                    {
                        ResultType = BrowserResultType.HttpError,
                        Error = error,
                        ErrorDescription = errorDescription
                    };
                }
                else
                {
                    _result = new BrowserResult
                    {
                        ResultType = BrowserResultType.Success,
                        Response = callbackUrl
                    };
                }

                // Signal that the callback was received
                try
                {
                    _semaphore.Release();
                }
                catch (SemaphoreFullException)
                {
                    Log.Warning("Semaphore already released, ignoring");
                }
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error processing callback");
                _result = new BrowserResult
                {
                    ResultType = BrowserResultType.UnknownError,
                    Error = ex.Message
                };

                try
                {
                    _semaphore.Release();
                }
                catch (SemaphoreFullException)
                {
                    Log.Warning("Semaphore already released after error");
                }
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            try
            {
                // Unsubscribe from callback handlers
                CustomSchemeProtocolHandler.CallbackReceived -= _callbackHandler;
                IpcCallbackHandler.CallbackReceived -= _callbackHandler;
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Error unsubscribing callback handlers");
            }

            try
            {
                _semaphore?.Dispose();
            }
            catch (Exception ex)
            {
                Log.Warning(ex, "Error disposing semaphore");
            }
        }
    }

    /// <summary>
    /// Handles Windows custom URL protocol registration and callback processing for wpfoidc:// scheme
    /// </summary>
    public static class CustomSchemeProtocolHandler
    {
        private static bool _isRegistered = false;
        private static string? _lastCallbackUrl;

        public static event EventHandler<string>? CallbackReceived;

        /// <summary>
        /// Register the wpfoidc:// custom URL scheme in Windows Registry
        /// </summary>
        public static void RegisterScheme()
        {
            if (_isRegistered) return;

            try
            {
                // Use the modern CustomSchemeRegistrar
                if (!CustomSchemeRegistrar.IsSchemeRegistered())
                {
                    CustomSchemeRegistrar.RegisterScheme();
                }

                _isRegistered = true;
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Failed to register custom URL scheme");
            }
        }

        /// <summary>
        /// Process command line arguments to extract callback URL
        /// </summary>
        public static async Task ProcessCommandLineArgsAsync(string[] args)
        {
            if (args == null || args.Length == 0) return;

            foreach (var arg in args)
            {
                // Look for wpfoidc:// scheme URL
                if (arg.StartsWith("wpfoidc://", StringComparison.OrdinalIgnoreCase))
                {
                    // Prevent duplicate processing
                    if (_lastCallbackUrl == arg)
                    {
                        return;
                    }

                    _lastCallbackUrl = arg;

                    // Try to send to running instance via IPC first
                    var sent = await IpcCallbackHandler.SendCallbackToRunningInstanceAsync(arg);

                    if (!sent)
                    {
                        CallbackReceived?.Invoke(null, arg);
                    }
                    else
                    {
                        Log.Information("Callback forwarded to running instance");
                    }

                    break;
                }
            }
        }

        /// <summary>
        /// Activate an existing instance of the application
        /// </summary>
        public static bool ActivateExistingInstance()
        {
            var currentProcess = Process.GetCurrentProcess();
            var processes = Process.GetProcessesByName(currentProcess.ProcessName);

            foreach (var process in processes)
            {
                if (process.Id != currentProcess.Id)
                {
                    // Found another instance, try to activate it
                    try
                    {
                        NativeMethods.SetForegroundWindow(process.MainWindowHandle);
                        NativeMethods.ShowWindow(process.MainWindowHandle, NativeMethods.SW_RESTORE);
                        return true;
                    }
                    catch (Exception ex)
                    {
                        Log.Warning(ex, "Failed to activate existing instance");
                    }
                }
            }

            return false;
        }
    }

    /// <summary>
    /// Native Windows API methods for window activation
    /// </summary>
    internal static class NativeMethods
    {
        [DllImport("user32.dll")]
        public static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        public const int SW_RESTORE = 9;
    }
}
