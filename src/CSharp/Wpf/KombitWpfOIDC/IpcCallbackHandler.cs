using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
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
    private static readonly object _lockObject = new object();

    public static event EventHandler<string>? CallbackReceived;

    /// <summary>
    /// Start listening for callbacks from other instances
    /// </summary>
    public static void StartListening()
    {
        lock (_lockObject)
        {
            if (_isListening) return;

            _isListening = true;
            Task.Run(async () => await ListenForCallbacksAsync());
            Log.Information("IPC callback listener started on pipe: {PipeName}", PipeName);
        }
    }

    /// <summary>
    /// Stop listening for callbacks
    /// </summary>
    public static void StopListening()
    {
        lock (_lockObject)
        {
            _isListening = false;
            _pipeServer?.Dispose();
            _pipeServer = null;
            Log.Information("IPC callback listener stopped");
        }
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
            var timeoutTask = Task.Delay(2000);
            var completedTask = await Task.WhenAny(connectTask, timeoutTask);
            
            if (completedTask == timeoutTask)
            {
                Log.Warning("Timeout connecting to pipe server");
                return false;
            }

            // Await the connect task to propagate any exceptions
            await connectTask;

            // Verify connection state
            if (!pipeClient.IsConnected)
            {
                Log.Warning("Pipe client failed to connect");
                return false;
            }

            // Send the callback URL
            var data = Encoding.UTF8.GetBytes(callbackUrl);
            await pipeClient.WriteAsync(data, 0, data.Length);
            await pipeClient.FlushAsync();

            Log.Information("Callback sent to running instance via IPC: {Url}", callbackUrl);
            return true;
        }
        catch (UnauthorizedAccessException ex)
        {
            Log.Warning(ex, "Access denied when connecting to pipe - server may not be ready yet");
            return false;
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
            NamedPipeServerStream? currentServer = null;
            
            try
            {
                // Create pipe security to allow current user
                var pipeSecurity = new PipeSecurity();
                var identity = WindowsIdentity.GetCurrent();
                var userSid = identity.User;
                
                if (userSid != null)
                {
                    // Allow current user full access
                    pipeSecurity.AddAccessRule(new PipeAccessRule(
                        userSid,
                        PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
                        AccessControlType.Allow));
                }

                // Create a new pipe server for each connection
                currentServer = NamedPipeServerStreamAcl.Create(
                    PipeName,
                    PipeDirection.In,
                    1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous,
                    inBufferSize: 4096,
                    outBufferSize: 4096,
                    pipeSecurity);

                lock (_lockObject)
                {
                    _pipeServer = currentServer;
                }

                Log.Debug("Waiting for IPC callback connection...");

                // Wait for client connection
                await currentServer.WaitForConnectionAsync();

                if (!_isListening)
                {
                    break;
                }

                Log.Debug("IPC client connected, reading callback...");

                // Read the callback URL
                using var reader = new StreamReader(currentServer, Encoding.UTF8);
                var callbackUrl = await reader.ReadToEndAsync();

                if (!string.IsNullOrWhiteSpace(callbackUrl))
                {
                    Log.Information("Received callback via IPC: {Url}", callbackUrl);
                    CallbackReceived?.Invoke(null, callbackUrl);
                }

                // Dispose current server before creating new one
                currentServer.Dispose();
                currentServer = null;
                
                lock (_lockObject)
                {
                    if (_pipeServer == currentServer)
                    {
                        _pipeServer = null;
                    }
                }
            }
            catch (Exception ex) when (_isListening)
            {
                Log.Error(ex, "Error in IPC callback listener");
                
                // Clean up current server
                if (currentServer != null)
                {
                    try
                    {
                        currentServer.Dispose();
                    }
                    catch { }
                }
                
                lock (_lockObject)
                {
                    _pipeServer = null;
                }
                
                await Task.Delay(1000); // Wait before retrying
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Error in IPC callback listener (shutting down)");
                
                // Clean up on shutdown
                if (currentServer != null)
                {
                    try
                    {
                        currentServer.Dispose();
                    }
                    catch { }
                }
                
                break;
            }
        }
        
        Log.Information("IPC callback listener loop exited");
    }
}
