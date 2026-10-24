using System;
using System.IO;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

namespace WebAppNetCore.EmergencyCredential
{
    public sealed class ProtectedStateStore : IDisposable
    {
        private readonly string path;
        private readonly FileStream ownership;
        private readonly IDataProtector protector;
        private LocalState state;
        private bool disposed;
        private bool faulted;
        public object Gate { get; } = new object();

        public ProtectedStateStore(EmergencyOptions options, IDataProtectionProvider provider, CredentialVerifier verifier)
        {
            Directory.CreateDirectory(options.StorageDirectory);
            ownership = new FileStream(Path.Combine(options.StorageDirectory, "owner.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            protector = provider.CreateProtector("OidcSample.Emergency.State.v1", options.Audience);
            path = Path.Combine(options.StorageDirectory, "state.bin");
            string marker = Path.Combine(options.StorageDirectory, "initialized");
            string disabled = Path.Combine(options.StorageDirectory, "support-disabled");
            try
            {
                if (File.Exists(path))
                {
                    if (new FileInfo(path).Length > 16777216)
                    {
                        throw new InvalidOperationException();
                    }
                    state = JsonSerializer.Deserialize<LocalState>(protector.Unprotect(File.ReadAllBytes(path)));
                    if (state == null || state.Version != 1 || state.Bindings == null || state.Credentials == null || state.Sessions == null)
                    {
                        throw new InvalidOperationException();
                    }
                    if (state.IssuerTrustRefreshRequired)
                    {
                        if (state.SigningKeys != null || state.Sessions.Count != 0)
                        {
                            throw new InvalidOperationException();
                        }
                    }
                    else
                    {
                        CredentialVerifier.ValidateKeys(state.SigningKeys);
                    }
                }
                else
                {
                    if (File.Exists(marker))
                    {
                        throw new InvalidOperationException();
                    }
                    string keys = File.ReadAllText(options.TrustedSigningKeysFile);
                    CredentialVerifier.ValidateKeys(keys);
                    state = new LocalState { SigningKeys = keys };
                    Persist(state);
                }
                if (File.Exists(disabled))
                {
                    state.Generation++;
                    state.Sessions.Clear();
                    Persist(state);
                    File.Delete(disabled);
                }
                File.WriteAllText(marker, "1");
            }
            catch { ownership.Dispose(); throw; }
        }
        public T Read<T>(Func<LocalState, T> read)
        {
            lock (Gate)
            {
                RequireOpen();
                return read(state);
            }
        }
        public T Update<T>(Func<LocalState, T> update)
        {
            lock (Gate)
            {
                RequireOpen();
                LocalState next = JsonSerializer.Deserialize<LocalState>(JsonSerializer.SerializeToUtf8Bytes(state));
                T result = update(next);
                try
                {
                    Persist(next);
                }
                catch { faulted = true; throw; }
                state = next;
                return result;
            }
        }
        private void Persist(LocalState next)
        {
            byte[] bytes = protector.Protect(JsonSerializer.SerializeToUtf8Bytes(next));
            if (bytes.Length > 16777216)
            {
                throw new EmergencyFault(503, "state_capacity");
            }
            string temporary = path + "." + StrictJson.Id() + ".tmp";
            try
            {
                using (FileStream file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                {
                    file.Write(bytes, 0, bytes.Length);
                    file.Flush(true);
                }
                if (File.Exists(path))
                {
                    File.Replace(temporary, path, null);
                }
                else
                {
                    File.Move(temporary, path);
                }
            }
            finally { if (File.Exists(temporary)) { File.Delete(temporary); } }
        }
        private void RequireOpen()
        {
            if (disposed)
            {
                throw new ObjectDisposedException(nameof(ProtectedStateStore));
            }
            if (faulted)
            {
                throw new EmergencyFault(503, "state_unavailable");
            }
        }
        public void Dispose()
        {
            lock (Gate)
            {
                if (!disposed)
                {
                    disposed = true;
                    ownership.Dispose();
                }
            }
        }
    }
}
