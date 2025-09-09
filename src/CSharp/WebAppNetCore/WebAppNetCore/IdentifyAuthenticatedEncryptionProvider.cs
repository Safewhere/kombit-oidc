using System;
using System.Linq;
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
                
                Console.WriteLine($"DecryptWithCbcHs: Algorithm={Algorithm}");
                Console.WriteLine($"DecryptWithCbcHs: Key length={symmetricKey.Length} bytes");
                Console.WriteLine($"DecryptWithCbcHs: AAD length={authenticatedData?.Length ?? 0} bytes");
                Console.WriteLine($"DecryptWithCbcHs: IV length={iv.Length} bytes");
                Console.WriteLine($"DecryptWithCbcHs: Ciphertext length={ciphertext.Length} bytes");
                Console.WriteLine($"DecryptWithCbcHs: Auth tag length={authenticationTag.Length} bytes");

                if (authenticatedData != null)
                {
                    Console.WriteLine($"DecryptWithCbcHs: AAD as string: {System.Text.Encoding.ASCII.GetString(authenticatedData)}");
                    Console.WriteLine($"DecryptWithCbcHs: AAD hex (first 32 bytes): {Convert.ToHexString(authenticatedData.Take(Math.Min(32, authenticatedData.Length)).ToArray())}");
                }

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

                // Split the key according to RFC 7518 Section 4.1.4
                // For AES_192_CBC_HMAC_SHA_384:
                // - First 192 bits (24 bytes) = MAC key
                // - Second 192 bits (24 bytes) = Encryption key
                var macKey = new byte[macKeySize];
                var encKey = new byte[encKeySize];
                Array.Copy(symmetricKey, 0, macKey, 0, macKeySize);
                Array.Copy(symmetricKey, macKeySize, encKey, 0, encKeySize);
                
                Console.WriteLine($"DecryptWithCbcHs: MAC key: {Convert.ToHexString(macKey)}");
                Console.WriteLine($"DecryptWithCbcHs: Enc key: {Convert.ToHexString(encKey)}");

                // Try both interpretations of RFC 7518 - with and without the AL field
                // to see which one produces the correct HMAC
                
                // Version 1: Without AL field (some implementations don't include it)
                var authInputLength1 = (authenticatedData?.Length ?? 0) + iv.Length + ciphertext.Length;
                var authInput1 = new byte[authInputLength1];
                int offset1 = 0;

                if (authenticatedData != null && authenticatedData.Length > 0)
                {
                    Array.Copy(authenticatedData, 0, authInput1, offset1, authenticatedData.Length);
                    offset1 += authenticatedData.Length;
                }
                Array.Copy(iv, 0, authInput1, offset1, iv.Length);
                offset1 += iv.Length;
                Array.Copy(ciphertext, 0, authInput1, offset1, ciphertext.Length);

                // Version 2: With AL field in bits
                var aadLength = authenticatedData?.Length ?? 0;
                var aadLengthBits = (long)aadLength * 8;
                var aadLengthBytes = BitConverter.GetBytes(aadLengthBits);
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(aadLengthBytes);
                }
                
                var authInputLength2 = aadLength + iv.Length + ciphertext.Length + 8;
                var authInput2 = new byte[authInputLength2];
                int offset2 = 0;

                if (authenticatedData != null && authenticatedData.Length > 0)
                {
                    Array.Copy(authenticatedData, 0, authInput2, offset2, authenticatedData.Length);
                    offset2 += authenticatedData.Length;
                }
                Array.Copy(iv, 0, authInput2, offset2, iv.Length);
                offset2 += iv.Length;
                Array.Copy(ciphertext, 0, authInput2, offset2, ciphertext.Length);
                offset2 += ciphertext.Length;
                Array.Copy(aadLengthBytes, 0, authInput2, offset2, 8);

                // Version 3: With AL field in bytes (octets)
                var aadLengthOctets = (long)aadLength;
                var aadLengthOctetsBytes = BitConverter.GetBytes(aadLengthOctets);
                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(aadLengthOctetsBytes);
                }
                
                var authInputLength3 = aadLength + iv.Length + ciphertext.Length + 8;
                var authInput3 = new byte[authInputLength3];
                int offset3 = 0;

                if (authenticatedData != null && authenticatedData.Length > 0)
                {
                    Array.Copy(authenticatedData, 0, authInput3, offset3, authenticatedData.Length);
                    offset3 += authenticatedData.Length;
                }
                Array.Copy(iv, 0, authInput3, offset3, iv.Length);
                offset3 += iv.Length;
                Array.Copy(ciphertext, 0, authInput3, offset3, ciphertext.Length);
                offset3 += ciphertext.Length;
                Array.Copy(aadLengthOctetsBytes, 0, authInput3, offset3, 8);

                Console.WriteLine($"DecryptWithCbcHs: Trying 3 different HMAC constructions...");
                Console.WriteLine($"DecryptWithCbcHs: Version 1 (no AL): {authInput1.Length} bytes");
                Console.WriteLine($"DecryptWithCbcHs: Version 2 (AL in bits): {authInput2.Length} bytes, AL={aadLengthBits} -> {Convert.ToHexString(aadLengthBytes)}");
                Console.WriteLine($"DecryptWithCbcHs: Version 3 (AL in octets): {authInput3.Length} bytes, AL={aadLengthOctets} -> {Convert.ToHexString(aadLengthOctetsBytes)}");

                // Test all three versions
                var authInputs = new[] { authInput1, authInput2, authInput3 };
                var versions = new[] { "no AL", "AL in bits", "AL in octets" };

                for (int i = 0; i < authInputs.Length; i++)
                {
                    byte[] computedTag = new byte[macSize];
                    
                    switch (hashAlgorithm.Name)
                    {
                        case "SHA256":
                            using (var hmac256 = new HMACSHA256(macKey))
                            {
                                var fullMac = hmac256.ComputeHash(authInputs[i]);
                                Array.Copy(fullMac, 0, computedTag, 0, macSize);
                            }
                            break;
                        case "SHA384":
                            using (var hmac384 = new HMACSHA384(macKey))
                            {
                                var fullMac = hmac384.ComputeHash(authInputs[i]);
                                Array.Copy(fullMac, 0, computedTag, 0, macSize);
                            }
                            break;
                        case "SHA512":
                            using (var hmac512 = new HMACSHA512(macKey))
                            {
                                var fullMac = hmac512.ComputeHash(authInputs[i]);
                                Array.Copy(fullMac, 0, computedTag, 0, macSize);
                            }
                            break;
                    }

                    Console.WriteLine($"DecryptWithCbcHs: Version {i+1} ({versions[i]}) - Computed tag: {Convert.ToHexString(computedTag)}");
                    
                    if (ConstantTimeEquals(computedTag, authenticationTag))
                    {
                        Console.WriteLine($"DecryptWithCbcHs: HMAC verification successful with version {i+1} ({versions[i]})!");
                        
                        // Use the correct authInput for further processing
                        // Decrypt with AES-CBC
                        using (var aes = Aes.Create())
                        {
                            aes.Mode = CipherMode.CBC;
                            aes.Padding = PaddingMode.PKCS7;
                            aes.Key = encKey;
                            aes.IV = iv;

                            using (var decryptor = aes.CreateDecryptor())
                            {
                                var decryptedBytes = decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                                Console.WriteLine($"DecryptWithCbcHs: AES-CBC decryption successful, plaintext length={decryptedBytes.Length} bytes");
                                
                                try 
                                {
                                    var testString = System.Text.Encoding.UTF8.GetString(decryptedBytes);
                                    Console.WriteLine($"DecryptWithCbcHs: Decrypted text preview: {testString.Substring(0, Math.Min(100, testString.Length))}...");
                                }
                                catch 
                                {
                                    Console.WriteLine($"DecryptWithCbcHs: Warning - Decrypted bytes do not appear to be valid UTF-8");
                                }
                                
                                return decryptedBytes;
                            }
                        }
                    }
                }

                Console.WriteLine($"DecryptWithCbcHs: Expected tag: {Convert.ToHexString(authenticationTag)}");
                Console.WriteLine($"HMAC verification failed for algorithm {Algorithm} - none of the 3 versions matched");
                throw new SecurityTokenDecryptionFailedException("Authentication tag verification failed.");
            }
            catch (Exception ex) when (!(ex is SecurityTokenDecryptionFailedException))
            {
                Console.WriteLine($"DecryptWithCbcHs: Exception - {ex.Message}");
                Console.WriteLine($"DecryptWithCbcHs: Exception type - {ex.GetType().Name}");
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
