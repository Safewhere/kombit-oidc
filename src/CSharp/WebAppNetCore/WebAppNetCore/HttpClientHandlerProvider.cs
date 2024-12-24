using System.Net.Http;

namespace WebAppNetCore
{
    public static class HttpClientHandlerProvider
    {
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
