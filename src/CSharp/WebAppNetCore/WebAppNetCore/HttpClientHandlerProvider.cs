using System.Net.Http;
using System.Security.Cryptography.X509Certificates;

namespace WebAppNetCore
{
    public static class HttpClientHandlerProvider
    {
        /// <summary>
        /// A handler that presents the client certificate in the TLS handshake, for mutual TLS (RFC 8705).
        /// </summary>
        public static HttpClientHandler Create(X509Certificate2 clientCertificate)
        {
            var handler = Create();
            handler.ClientCertificateOptions = ClientCertificateOption.Manual;
            handler.ClientCertificates.Add(clientCertificate);
            return handler;
        }

        public static HttpClientHandler Create()
        {
#if DEBUG
#warning This is for testing purpose only. In reality, all production sites must use trusted SSL certificate which will never cause any problem with validation.
            return new HttpClientHandler()
            {
                ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => { return true; }
            };
#endif

            return new HttpClientHandler();
        }
    }
}
