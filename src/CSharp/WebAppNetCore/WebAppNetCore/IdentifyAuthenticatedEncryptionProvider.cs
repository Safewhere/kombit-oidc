using System;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace WebAppNetCore
{
    public class IdentifyAuthenticatedEncryptionProvider : AuthenticatedEncryptionProvider
    {
        public IdentifyAuthenticatedEncryptionProvider(SecurityKey key, string algorithm) : base(key, algorithm)
        {
        }

        public override byte[] Decrypt(byte[] ciphertext, byte[] authenticatedData, byte[] iv, byte[] authenticationTag)
        {
            if (ciphertext == null)
                throw new ArgumentNullException(nameof(ciphertext));
            if (iv == null)
                throw new ArgumentNullException(nameof(iv));
            if (authenticationTag == null)
                throw new ArgumentNullException(nameof(authenticationTag));

            if (Algorithm.Contains("CBC-HS"))
            {
                return DecryptWithCbcHs(ciphertext, authenticatedData, iv, authenticationTag);
            }
            return DecryptWithAesGcm(ciphertext, authenticatedData, iv, authenticationTag);
        }

        private byte[] DecryptWithAesGcm(byte[] ciphertext, byte[] authenticatedData, byte[] iv, byte[] authenticationTag)
        {
            try
            {
                Console.WriteLine($"DecryptWithAesGcm: Algorithm={Algorithm}");
                Console.WriteLine($"DecryptWithAesGcm: Ciphertext length={ciphertext.Length}, IV length={iv.Length}, AuthTag length={authenticationTag.Length}");
                Console.WriteLine($"DecryptWithAesGcm: AuthenticatedData length={authenticatedData?.Length ?? 0}");

                var symmetricKey = ((SymmetricSecurityKey)Key).Key;
                Console.WriteLine($"DecryptWithAesGcm: Symmetric key length={symmetricKey.Length}");

                // Standard AES-GCM tag size is 16 bytes (128 bits)
                // Don't specify tag size in constructor - let AesGcm use default
                using (var aes = new AesGcm(symmetricKey))
                {
                    var plaintext = new byte[ciphertext.Length];

                    // For AES-GCM, authenticated data can be null
                    byte[] aad = authenticatedData ?? new byte[0];

                    Console.WriteLine($"DecryptWithAesGcm: Calling aes.Decrypt...");
                    aes.Decrypt(iv, ciphertext, authenticationTag, plaintext, aad);

                    Console.WriteLine($"DecryptWithAesGcm: Decryption successful, plaintext length={plaintext.Length}");
                    return plaintext;
                }
            }
            catch (AuthenticationTagMismatchException ex)
            {
                Console.WriteLine($"DecryptWithAesGcm: Authentication tag mismatch - {ex.Message}");
                Console.WriteLine($"Expected tag length for algorithm {Algorithm}: 16 bytes");
                Console.WriteLine($"Actual tag length: {authenticationTag.Length} bytes");
                Console.WriteLine($"IV length: {iv.Length} bytes");
                Console.WriteLine($"Key length: {((SymmetricSecurityKey)Key).Key.Length} bytes");
                throw new SecurityTokenDecryptionFailedException("AES-GCM authentication tag verification failed.", ex);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"DecryptWithAesGcm: Exception - {ex.Message}");
                Console.WriteLine($"Exception type: {ex.GetType().Name}");
                throw new SecurityTokenDecryptionFailedException("Failed to decrypt with AES-GCM.", ex);
            }
        }

        private byte[] DecryptWithCbcHs(byte[] ciphertext, byte[] authenticatedData, byte[] iv, byte[] authenticationTag)
        {
            try
            {
                var symmetricKey = ((Microsoft.IdentityModel.Tokens.SymmetricSecurityKey)Key).Key;

                // Determine key sizes based on algorithm
                int macKeySize, encKeySize, macSize;
                HashAlgorithmName hashAlgorithm;

                switch (Algorithm)
                {
                    case "A128CBC-HS256":
                        macKeySize = 16; // 128 bits
                        encKeySize = 16; // 128 bits
                        macSize = 16; // 128 bits (truncated from 256)
                        hashAlgorithm = HashAlgorithmName.SHA256;
                        break;
                    case "A192CBC-HS384":
                        macKeySize = 24; // 192 bits
                        encKeySize = 24; // 192 bits
                        macSize = 24; // 192 bits (truncated from 384)
                        hashAlgorithm = HashAlgorithmName.SHA384;
                        break;
                    case "A256CBC-HS512":
                        macKeySize = 32; // 256 bits
                        encKeySize = 32; // 256 bits
                        macSize = 32; // 256 bits (truncated from 512)
                        hashAlgorithm = HashAlgorithmName.SHA512;
                        break;
                    default:
                        throw new NotSupportedException($"Algorithm {Algorithm} is not supported");
                }

                // Split the key
                var macKey = new byte[macKeySize];
                var encKey = new byte[encKeySize];
                Array.Copy(symmetricKey, 0, macKey, 0, macKeySize);
                Array.Copy(symmetricKey, macKeySize, encKey, 0, encKeySize);

                // Verify authentication tag
                var authInput = new byte[(authenticatedData?.Length ?? 0) + iv.Length + ciphertext.Length];
                int offset = 0;

                if (authenticatedData != null)
                {
                    Array.Copy(authenticatedData, 0, authInput, offset, authenticatedData.Length);
                    offset += authenticatedData.Length;
                }

                Array.Copy(iv, 0, authInput, offset, iv.Length);
                offset += iv.Length;
                Array.Copy(ciphertext, 0, authInput, offset, ciphertext.Length);

                // Compute and verify HMAC
                byte[] computedTag = new byte[macSize];
                switch (hashAlgorithm.Name)
                {
                    case "SHA256":
                        using (var hmac256 = new HMACSHA256(macKey))
                        {
                            var fullMac = hmac256.ComputeHash(authInput);
                            Array.Copy(fullMac, 0, computedTag, 0, macSize);
                        }
                        break;
                    case "SHA384":
                        using (var hmac384 = new HMACSHA384(macKey))
                        {
                            var fullMac = hmac384.ComputeHash(authInput);
                            Array.Copy(fullMac, 0, computedTag, 0, macSize);
                        }
                        break;
                    case "SHA512":
                        using (var hmac512 = new HMACSHA512(macKey))
                        {
                            var fullMac = hmac512.ComputeHash(authInput);
                            Array.Copy(fullMac, 0, computedTag, 0, macSize);
                        }
                        break;
                }

                // Constant-time comparison to prevent timing attacks
                if (!ConstantTimeEquals(computedTag, authenticationTag))
                {
                    throw new SecurityTokenDecryptionFailedException("Authentication tag verification failed.");
                }

                // Decrypt with AES-CBC
                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Key = encKey;
                    aes.IV = iv;

                    using (var decryptor = aes.CreateDecryptor())
                    {
                        return decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                    }
                }
            }
            catch (Exception ex) when (!(ex is SecurityTokenDecryptionFailedException))
            {
                throw new SecurityTokenDecryptionFailedException("Failed to decrypt with AES-CBC-HS.", ex);
            }
        }

        /// <summary>
        /// Performs constant-time comparison of two byte arrays to prevent timing attacks.
        /// </summary>
        private static bool ConstantTimeEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length)
                return false;

            int result = 0;
            for (int i = 0; i < a.Length; i++)
            {
                result |= a[i] ^ b[i];
            }

            return result == 0;
        }
    }
}
