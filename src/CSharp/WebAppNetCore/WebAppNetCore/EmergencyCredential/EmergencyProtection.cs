using System;
using System.IO;
using Microsoft.AspNetCore.DataProtection;

namespace WebAppNetCore.EmergencyCredential
{
    public sealed class EmergencyProtection
    {
        private readonly Lazy<IDataProtectionProvider> provider;
        public EmergencyProtection(EmergencyOptions options)
        {
            provider = new Lazy<IDataProtectionProvider>(() => DataProtectionProvider.Create(new DirectoryInfo(options.ProtectionKeysDirectory), builder => { builder.SetApplicationName("OidcSampleEmergency:" + options.Audience); if (OperatingSystem.IsWindows()) { builder.ProtectKeysWithDpapi(true); } }));
        }
        public IDataProtectionProvider Provider => new DeferredProvider(provider);
        private sealed class DeferredProvider : IDataProtectionProvider
        {
            private readonly Lazy<IDataProtectionProvider> provider;
            public DeferredProvider(Lazy<IDataProtectionProvider> value)
            {
                provider = value;
            }
            public IDataProtector CreateProtector(string purpose) => provider.Value.CreateProtector(purpose);
        }
    }
}
