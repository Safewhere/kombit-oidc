using System.Configuration;
using System.Data;
using System.Windows;
using KombitWpfOIDC;
using Serilog;

namespace KomitWpfOIDC
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            LoggerConfig.Init();
            base.OnStartup(e);
        }
        protected override void OnExit(ExitEventArgs e)
        {
            Log.Information("App exiting");
            Log.CloseAndFlush();
            base.OnExit(e);
        }
    }

}
