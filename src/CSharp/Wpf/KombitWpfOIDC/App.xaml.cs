using System.Configuration;
using System.Data;
using System.Threading;
using System.Windows;
using KombitWpfOIDC;
using Serilog;

namespace KombitWpfOIDC
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        private static Mutex? _mutex;
        private const string MutexName = "KombitWpfOIDC_SingleInstance";

        protected override async void OnStartup(StartupEventArgs e)
        {
            // Initialize logger first
            LoggerConfig.Init();

            // Check if another instance is already running
            _mutex = new Mutex(true, MutexName, out bool isNewInstance);

            if (!isNewInstance)
            {
                // Process command line args and send to running instance
                if (e.Args.Length > 0)
                {
                    await CustomSchemeProtocolHandler.ProcessCommandLineArgsAsync(e.Args);
                }

                CustomSchemeProtocolHandler.ActivateExistingInstance();

                // Exit this instance
                Shutdown();
                return;
            }

            // Start IPC listener for callbacks from secondary instances
            IpcCallbackHandler.StartListening();

            // Process command line arguments for custom scheme callbacks
            // (in case this is the first launch WITH a callback URL)
            if (e.Args.Length > 0)
            {
                await CustomSchemeProtocolHandler.ProcessCommandLineArgsAsync(e.Args);
            }

            await ConfigurationExtensions.GetDiscoveryAsync();
            base.OnStartup(e);
        }

        protected override void OnExit(ExitEventArgs e)
        {
            Log.Information("App exiting");
            IpcCallbackHandler.StopListening();

            Log.CloseAndFlush();
            _mutex?.ReleaseMutex();
            _mutex?.Dispose();
            base.OnExit(e);
        }
    }
}
