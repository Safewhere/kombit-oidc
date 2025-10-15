using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace KomitWpfOIDC
{
    delegate byte[] EncryptDelegate(byte[] bytes);
    delegate byte[] DecryptDelegate(byte[] bytes);
    delegate byte[] SignDelegate(byte[] bytes);
    delegate bool VerifyDelegate(byte[] bytes, byte[] signature);
    delegate bool VerifyDelegateWithLength(byte[] bytes, int start, int length, byte[] signature);

    public class IdentifyAsymmetricAdapter : IDisposable
    {
        private bool _disposeCryptoOperators = false;
        private bool _disposed = false;
        private DecryptDelegate DecryptFunction = DecryptFunctionNotFound;
        private EncryptDelegate EncryptFunction = EncryptFunctionNotFound;
        private SignDelegate SignatureFunction = SignatureFunctionNotFound;
        private VerifyDelegate VerifyFunction = VerifyFunctionNotFound;
        private VerifyDelegateWithLength VerifyFunctionWithLength = VerifyFunctionWithLengthNotFound;

        // Encryption algorithms do not need a HashAlgorithm, this is called by RSAKeyWrap
        internal IdentifyAsymmetricAdapter(SecurityKey key, string algorithm, bool requirePrivateKey)
            : this(key, algorithm, null, requirePrivateKey)
        {
        }

        // This constructor will be used by NET45 for signing and for RSAKeyWrap
        internal IdentifyAsymmetricAdapter(SecurityKey key, string algorithm, HashAlgorithm hashAlgorithm, bool requirePrivateKey)
        {
            HashAlgorithm = hashAlgorithm;

            // RsaSecurityKey has either Rsa OR RsaParameters.
            // If we use the RsaParameters, we create a new RSA object and will need to dispose.
            if (key is RsaSecurityKey rsaKey)
            {
                InitializeUsingRsaSecurityKey(rsaKey, algorithm);
            }
            else if (key is X509SecurityKey x509Key)
            {
                InitializeUsingX509SecurityKey(x509Key, algorithm, requirePrivateKey);
            }
            else if (key is ECDsaSecurityKey ecdsaKey)
            {
                InitializeUsingEcdsaSecurityKey(ecdsaKey);
            }
            else
                throw new NotSupportedException(algorithm);
        }

        internal byte[] Decrypt(byte[] data)
        {
            return DecryptFunction(data);
        }

        internal static byte[] DecryptFunctionNotFound(byte[] _)
        {
            // we should never get here, its a bug if we do.
            throw new NotSupportedException("DecryptFunctionNotFound");
        }

        /// <summary>
        /// Calls <see cref="Dispose(bool)"/> and <see cref="GC.SuppressFinalize"/>
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                _disposed = true;
                if (disposing)
                {
                    if (_disposeCryptoOperators)
                    {
                        if (ECDsa != null)
                            ECDsa.Dispose();

                        if (RSA != null)
                            RSA.Dispose();
                    }
                }
            }
        }

        private ECDsa ECDsa { get; set; }

        internal byte[] Encrypt(byte[] data)
        {
            return EncryptFunction(data);
        }

        internal static byte[] EncryptFunctionNotFound(byte[] _)
        {
            // we should never get here, its a bug if we do.
            throw new NotSupportedException("EncryptFunctionNotFound");
        }

        private HashAlgorithm HashAlgorithm { get; set; }

        private void InitializeUsingEcdsaSecurityKey(ECDsaSecurityKey ecdsaSecurityKey)
        {
            ECDsa = ecdsaSecurityKey.ECDsa;
            SignatureFunction = SignWithECDsa;
            VerifyFunction = VerifyWithECDsa;
            VerifyFunctionWithLength = VerifyWithECDsaWithLength;
        }

        private void InitializeUsingRsa(RSA rsa, string algorithm)
        {
            // The return value for X509Certificate2.GetPrivateKey OR X509Certificate2.GetPublicKey.Key is a RSACryptoServiceProvider
            // These calls return an AsymmetricAlgorithm which doesn't have API's to do much and need to be cast.
            // RSACryptoServiceProvider is wrapped with RSACryptoServiceProviderProxy as some CryptoServideProviders (CSP's) do
            // not natively support SHA2.
#if DESKTOP
            if (rsa is RSACryptoServiceProvider rsaCryptoServiceProvider)
            {
                _useRSAOeapPadding = algorithm.Equals(SecurityAlgorithms.RsaOAEP)
                                  || algorithm.Equals(SecurityAlgorithms.RsaOaepKeyWrap);

                RsaCryptoServiceProviderProxy = new RSACryptoServiceProviderProxy(rsaCryptoServiceProvider);
                DecryptFunction = DecryptWithRsaCryptoServiceProviderProxy;
                EncryptFunction = EncryptWithRsaCryptoServiceProviderProxy;
                SignatureFunction = SignWithRsaCryptoServiceProviderProxy;
                VerifyFunction = VerifyWithRsaCryptoServiceProviderProxy;
#if NET461_OR_GREATER
                VerifyFunctionWithLength = VerifyWithRsaCryptoServiceProviderProxyWithLength;
#endif
                // RSACryptoServiceProviderProxy will track if a new RSA object is created and dispose appropriately.
                _disposeCryptoOperators = true;
                return;
            }
#endif

            // Set signature padding based on algorithm
            if (algorithm.Equals(SecurityAlgorithms.RsaSsaPssSha256) ||
                algorithm.Equals(SecurityAlgorithms.RsaSsaPssSha256Signature) ||
                algorithm.Equals(SecurityAlgorithms.RsaSsaPssSha384) ||
                algorithm.Equals(SecurityAlgorithms.RsaSsaPssSha384Signature) ||
                algorithm.Equals(SecurityAlgorithms.RsaSsaPssSha512) ||
                algorithm.Equals(SecurityAlgorithms.RsaSsaPssSha512Signature))
            {
                RSASignaturePadding = RSASignaturePadding.Pss;
            }
            else
            {
                // default RSASignaturePadding for other supported RSA algorithms is Pkcs1
                RSASignaturePadding = RSASignaturePadding.Pkcs1;
            }

            // Set encryption padding based on algorithm
            switch (algorithm)
            {
                case SecurityAlgorithms.RsaOAEP:
                case SecurityAlgorithms.RsaOaepKeyWrap:
                    RSAEncryptionPadding = RSAEncryptionPadding.OaepSHA1;
                    break;
                case "RSA-OAEP-256":
                    RSAEncryptionPadding = RSAEncryptionPadding.OaepSHA256;
                    break;
                default:
                    RSAEncryptionPadding = RSAEncryptionPadding.Pkcs1;
                    break;
            }

            Console.WriteLine($"RSA Algorithm: {algorithm}, Encryption Padding: {RSAEncryptionPadding}");

            RSA = rsa;
            DecryptFunction = DecryptWithRsa;
            EncryptFunction = EncryptWithRsa;
            SignatureFunction = SignWithRsa;
            VerifyFunction = VerifyWithRsa;
            VerifyFunctionWithLength = VerifyWithRsaWithLength;
        }

        private void InitializeUsingRsaSecurityKey(RsaSecurityKey rsaSecurityKey, string algorithm)
        {
            if (rsaSecurityKey.Rsa != null)
            {
                InitializeUsingRsa(rsaSecurityKey.Rsa, algorithm);
            }
            else
            {
#if NET472 || NET6_0
                var rsa = RSA.Create(rsaSecurityKey.Parameters);
#else
                var rsa = RSA.Create();
                rsa.ImportParameters(rsaSecurityKey.Parameters);
#endif
                InitializeUsingRsa(rsa, algorithm);
                _disposeCryptoOperators = true;
            }
        }

        private void InitializeUsingX509SecurityKey(X509SecurityKey x509SecurityKey, string algorithm, bool requirePrivateKey)
        {
            if (requirePrivateKey)
                InitializeUsingRsa(x509SecurityKey.PrivateKey as RSA, algorithm);
            else
                InitializeUsingRsa(x509SecurityKey.PublicKey as RSA, algorithm);
        }

        private RSA RSA { get; set; }

        internal byte[] Sign(byte[] bytes)
        {
            return SignatureFunction(bytes);
        }

        private static byte[] SignatureFunctionNotFound(byte[] _)
        {
            // we should never get here, its a bug if we do.
            throw new CryptographicException("EncryptFunctionNotFound");
        }

        private byte[] SignWithECDsa(byte[] bytes)
        {
            return ECDsa.SignHash(HashAlgorithm.ComputeHash(bytes));
        }

        internal bool Verify(byte[] bytes, byte[] signature)
        {
            return VerifyFunction(bytes, signature);
        }

        internal bool Verify(byte[] bytes, int start, int length, byte[] signature)
        {
            return VerifyFunctionWithLength(bytes, start, length, signature);
        }

        private static bool VerifyFunctionNotFound(byte[] bytes, byte[] signature)
        {
            // we should never get here, its a bug if we do.
            throw new NotSupportedException("VerifyFunctionNotFound");
        }

        private static bool VerifyFunctionWithLengthNotFound(byte[] bytes, int start, int length, byte[] signature)
        {
            // we should never get here, its a bug if we do.
            throw new NotSupportedException("VerifyFunctionWithLengthNotFound");
        }

        private bool VerifyWithECDsa(byte[] bytes, byte[] signature)
        {
            return ECDsa.VerifyHash(HashAlgorithm.ComputeHash(bytes), signature);
        }

        private bool VerifyWithECDsaWithLength(byte[] bytes, int start, int length, byte[] signature)
        {
            return ECDsa.VerifyHash(HashAlgorithm.ComputeHash(bytes, start, length), signature);
        }


        // HasAlgorithmName was introduced into Net46
        internal IdentifyAsymmetricAdapter(SecurityKey key, string algorithm, HashAlgorithm hashAlgorithm, HashAlgorithmName hashAlgorithmName, bool requirePrivateKey)
            : this(key, algorithm, hashAlgorithm, requirePrivateKey)
        {
            HashAlgorithmName = hashAlgorithmName;
        }

        private byte[] DecryptWithRsa(byte[] bytes)
        {
            try
            {
                Console.WriteLine($"DecryptWithRsa called with {bytes.Length} bytes, using padding: {RSAEncryptionPadding}");
                Console.WriteLine($"RSA key size: {RSA.KeySize} bits");
                Console.WriteLine($"RSA has private key: {(RSA as RSA)?.KeySize > 0}");
                
                var result = RSA.Decrypt(bytes, RSAEncryptionPadding);
                Console.WriteLine($"DecryptWithRsa successful, decrypted {result.Length} bytes");
                return result;
            }
            catch (CryptographicException ex)
            {
                Console.WriteLine($"DecryptWithRsa CryptographicException: {ex.Message}");
                Console.WriteLine($"Padding used: {RSAEncryptionPadding}");
                Console.WriteLine($"Input size: {bytes.Length} bytes");
                Console.WriteLine($"RSA key size: {RSA.KeySize} bits");
                throw;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"DecryptWithRsa Exception: {ex.Message}");
                throw;
            }
        }

        private byte[] EncryptWithRsa(byte[] bytes)
        {
            return RSA.Encrypt(bytes, RSAEncryptionPadding);
        }

        private HashAlgorithmName HashAlgorithmName { get; set; }

        private RSAEncryptionPadding RSAEncryptionPadding { get; set; }

        private RSASignaturePadding RSASignaturePadding { get; set; }

        private byte[] SignWithRsa(byte[] bytes)
        {
            return RSA.SignHash(HashAlgorithm.ComputeHash(bytes), HashAlgorithmName, RSASignaturePadding);
        }

        private bool VerifyWithRsa(byte[] bytes, byte[] signature)
        {
            return RSA.VerifyHash(HashAlgorithm.ComputeHash(bytes), signature, HashAlgorithmName, RSASignaturePadding);
        }

        private bool VerifyWithRsaWithLength(byte[] bytes, int start, int length, byte[] signature)
        {
            return RSA.VerifyHash(HashAlgorithm.ComputeHash(bytes, start, length), signature, HashAlgorithmName, RSASignaturePadding);
        }
    }
}
