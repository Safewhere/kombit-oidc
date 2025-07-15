using System;
using Microsoft.IdentityModel.Tokens;

namespace WebAppNetCore
{
    public class IdentifyRsaKeyWrapProvider : KeyWrapProvider
    {
        private Lazy<IdentifyAsymmetricAdapter> _asymmetricAdapter;
        private bool _disposed = false;

        /// <summary>
        /// Gets the KeyWrap algorithm that is being used.
        /// </summary>
        public override string Algorithm { get; }

        /// <summary>
        /// Gets or sets a user context for a <see cref="KeyWrapProvider"/>.
        /// </summary>
        /// <remarks>This is null by default. This is for use by the application and not used by this SDK.</remarks>
        public override string Context { get; set; }

        /// <summary>
        /// Gets the <see cref="SecurityKey"/> that is being used.
        /// </summary>
        public override SecurityKey Key { get; }

        public IdentifyRsaKeyWrapProvider(SecurityKey key, string algorithm)
        {
            Key = key;
            Algorithm = algorithm;
            _asymmetricAdapter = new Lazy<IdentifyAsymmetricAdapter>(CreateAsymmetricAdapter);
        }

        internal IdentifyAsymmetricAdapter CreateAsymmetricAdapter()
        {
            Console.WriteLine($"Creating asymmetric adapter for key: {Key.GetType().Name}, algorithm: {Algorithm}");
            return new IdentifyAsymmetricAdapter(Key, Algorithm, true); // Changed to require private key for decryption
        }

        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _disposed = true;
                    _asymmetricAdapter.Value.Dispose();
                }
            }
        }

        public override byte[] UnwrapKey(byte[] keyBytes)
        {
            if (keyBytes == null || keyBytes.Length == 0)
                throw new ArgumentNullException(nameof(keyBytes));

            if (_disposed)
                throw new ObjectDisposedException(GetType().ToString());

            try
            {
                Console.WriteLine($"UnwrapKey called with {keyBytes.Length} bytes using algorithm {Algorithm}");
                var result = _asymmetricAdapter.Value.Decrypt(keyBytes);
                Console.WriteLine($"UnwrapKey successful, decrypted {result.Length} bytes");
                return result;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"UnwrapKey failed: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
                throw new SecurityTokenKeyWrapException("UnwrapKey", ex);
            }
        }

        public override byte[] WrapKey(byte[] keyBytes)
        {
            if (keyBytes == null || keyBytes.Length == 0)
                throw new ArgumentNullException(nameof(keyBytes));

            if (_disposed)
                throw new ObjectDisposedException(GetType().ToString());

            try
            {
                Console.WriteLine($"WrapKey called with {keyBytes.Length} bytes using algorithm {Algorithm}");
                var result = _asymmetricAdapter.Value.Encrypt(keyBytes);
                Console.WriteLine($"WrapKey successful, encrypted {result.Length} bytes");
                return result;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"WrapKey failed: {ex.Message}");
                throw new SecurityTokenKeyWrapException("WrapKey", ex);
            }
        }
    }
}
