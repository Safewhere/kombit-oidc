using Microsoft.IdentityModel.Tokens;

namespace KomitWpfOIDC
{
    public class IdentifyCryptoProviderFactory : CryptoProviderFactory
    {
        public override KeyWrapProvider CreateKeyWrapProvider(SecurityKey key, string algorithm)
        {
            return new IdentifyRsaKeyWrapProvider(key, algorithm);
        }

        public override AuthenticatedEncryptionProvider CreateAuthenticatedEncryptionProvider(SecurityKey key, string algorithm)
        {
            return new IdentifyAuthenticatedEncryptionProvider(key, algorithm);
        }
    }
}
