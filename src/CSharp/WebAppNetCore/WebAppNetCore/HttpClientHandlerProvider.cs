using System.Net.Http;
using System.Security.Cryptography.X509Certificates;

namespace WebAppNetCore
{
    public static class HttpClientHandlerProvider
    {
        /// <summary>
        /// A handler that presents the client certificate in the TLS handshake, for mutual TLS (RFC 8705).
        /// </summary>
        public static HttpClientHandler Create(X509Certificate2 clientCertificate, bool acceptAnyServerCertificate)
        {
            var handler = Create(acceptAnyServerCertificate);
            handler.ClientCertificateOptions = ClientCertificateOption.Manual;
            handler.ClientCertificates.Add(clientCertificate);
            return handler;
        }

        /// <summary>
        /// A handler that validates the TLS server certificate. With acceptAnyServerCertificate (the setting
        /// Testing:AcceptAnyServerCertificate), it accepts every server certificate, for a test host with a certificate that the
        /// computer does not trust.
        /// </summary>
        public static HttpClientHandler Create(bool acceptAnyServerCertificate)
        {
            var handler = new HttpClientHandler();
            if (acceptAnyServerCertificate)
            {
                handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
            }

            return handler;
        }
    }
}
