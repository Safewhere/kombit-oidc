using System;
using System.IO;
using System.Text.Json;
using Serilog;

namespace KombitWpfOIDC
{
    public static class LoggerConfig
    {
        public static void Init()
        {
            var logPath = Path.Combine(AppContext.BaseDirectory, "logs", "komit-oidc-.log");
            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .WriteTo.Console()
                .WriteTo.File(
                    logPath,
                    rollingInterval: RollingInterval.Day,
                    retainedFileCountLimit: 10)
                .CreateLogger();
        }
        public static void InfoAsJson<T>(string message, T obj)
        {
            var json = JsonSerializer.Serialize(obj, new JsonSerializerOptions
            {
                WriteIndented = true,
                IgnoreNullValues = true
            });
            Log.Information("{Message}\n{Json}", message, json);
        }
    }
}
