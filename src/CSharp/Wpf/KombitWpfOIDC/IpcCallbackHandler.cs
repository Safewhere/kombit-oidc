using System.IO;
using System.IO.Pipes;
using System.Text;
using Serilog;

namespace KombitWpfOIDC;

/// <summary>
/// Inter-Process Communication handler for passing callback URLs between app instances
/// </summary>
public static class IpcCallbackHandler
{
    private const string PipeName = "KombitWpfOIDC_CallbackPipe";
    private static NamedPipeServerStream? _pipeServer;
    private static bool _isListening;

    public static event EventHandler<string>? CallbackReceived;

    /// <summary>
    /// Start listening for callbacks from other instances
    /// </summary>
    public static void StartListening()
    {
        if (_isListening) return;

        _isListening = true;
        Task.Run(async () => await ListenForCallbacksAsync());
        Log.Information("IPC callback listener started on pipe: {PipeName}", PipeName);
    }

    /// <summary>
    /// Stop listening for callbacks
    /// </summary>
    public static void StopListening()
    {
        _isListening = false;
        _pipeServer?.Dispose();
        _pipeServer = null;
        Log.Information("IPC callback listener stopped");
    }

    /// <summary>
    /// Send a callback URL to the running instance
    /// </summary>
    public static async Task<bool> SendCallbackToRunningInstanceAsync(string callbackUrl)
    {
        try
        {
            using var pipeClient = new NamedPipeClientStream(".", PipeName, PipeDirection.Out);

            // Try to connect with timeout
            var connectTask = pipeClient.ConnectAsync(2000);
            if (await Task.WhenAny(connectTask, Task.Delay(2000)) != connectTask)
            {
                Log.Warning("Timeout connecting to pipe server");
                return false;
            }

            // Send the callback URL
            var data = Encoding.UTF8.GetBytes(callbackUrl);
            await pipeClient.WriteAsync(data, 0, data.Length);
            await pipeClient.FlushAsync();

            Log.Information("Callback sent to running instance via IPC: {Url}", callbackUrl);
            return true;
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Failed to send callback to running instance");
            return false;
        }
    }

    private static async Task ListenForCallbacksAsync()
    {
        while (_isListening)
        {
            try
            {
                // Create a new pipe server for each connection
                _pipeServer = new NamedPipeServerStream(
                             PipeName,
                         PipeDirection.In,
                      1,
                       PipeTransmissionMode.Byte,
                         PipeOptions.Asynchronous);

                Log.Debug("Waiting for IPC callback connection...");

                // Wait for client connection
                await _pipeServer.WaitForConnectionAsync();

                Log.Debug("IPC client connected, reading callback...");

                // Read the callback URL
                using var reader = new StreamReader(_pipeServer, Encoding.UTF8);
                var callbackUrl = await reader.ReadToEndAsync();

                if (!string.IsNullOrWhiteSpace(callbackUrl))
                {
                    Log.Information("Received callback via IPC: {Url}", callbackUrl);
                    CallbackReceived?.Invoke(null, callbackUrl);
                }

                _pipeServer.Dispose();
                _pipeServer = null;
            }
            catch (Exception ex) when (_isListening)
            {
                Log.Error(ex, "Error in IPC callback listener");
                await Task.Delay(1000); // Wait before retrying
            }
        }
    }
}
