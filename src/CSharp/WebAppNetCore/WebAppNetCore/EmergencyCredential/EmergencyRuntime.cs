using System;
using System.IO;
using System.Net.Http;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;

namespace WebAppNetCore.EmergencyCredential
{
    public sealed class EmergencyRuntime : IDisposable
    {
        private readonly object gate = new object();
        private readonly Lazy<EmergencyService> service;
        private bool disposed;
        public EmergencyOptions Options { get; }
        public EmergencyRuntime(EmergencyOptions options, IDataProtectionProvider protection, IHttpClientFactory clients, IWebHostEnvironment environment, ILogger<EmergencyRuntime> log)
        {
            Options = options;
            if (!options.Enabled && !string.IsNullOrEmpty(options.StorageDirectory))
            {
                try
                {
                    EmergencyOptions.ExternalPath(options.StorageDirectory, environment.ContentRootPath);
                    if (Directory.Exists(options.StorageDirectory))
                    {
                        File.WriteAllText(Path.Combine(options.StorageDirectory, "support-disabled"), "1");
                    }
                }
                catch (Exception) { log.LogWarning("Emergency disabled-state marker unavailable. Local recovery is required before enabling support."); }
            }
            service = new Lazy<EmergencyService>(() =>
            {
                options.Validate(environment.ContentRootPath);
                CredentialVerifier verifier = new CredentialVerifier(options);
                return new EmergencyService(options, new ProtectedStateStore(options, protection, verifier), verifier,
                    new AssertionVerifier(options), new IssuerClient(options, clients.CreateClient("EmergencyIssuer")), TimeProvider.System);
            });
        }
        public EmergencyService Service
        {
            get
            {
                lock (gate)
                {
                    if (!Options.Enabled || disposed)
                    {
                        throw new EmergencyFault(404, "not_found");
                    }
                    try
                    {
                        return service.Value;
                    }
                    catch (EmergencyFault) { throw; }
                    catch (Exception exception) { throw new EmergencyFault(503, "emergency_unavailable", exception); }
                }
            }
        }
        public void Dispose()
        {
            lock (gate)
            {
                if (!disposed)
                {
                    disposed = true;
                    if (service.IsValueCreated)
                    {
                        service.Value.Dispose();
                    }
                }
            }
        }
    }
}
