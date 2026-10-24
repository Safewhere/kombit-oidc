using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace WebAppNetCore.EmergencyCredential
{
    public sealed class IssuerClient
    {
        private readonly EmergencyOptions options;
        private readonly HttpClient http;
        public IssuerClient(EmergencyOptions configuration, HttpClient client)
        {
            options = configuration;
            http = client;
        }
        public async Task<JsonElement> SendAsync(HttpMethod method, string relative, object body, CancellationToken cancellation)
        {
            int? status = null;
            bool received = false;
            var timer = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                using HttpRequestMessage request = new HttpRequestMessage(method, new Uri(new Uri(options.IssuerBaseUrl), relative));
                request.Headers.Add("X-Emergency-Client-Key", options.BackendKey());
                if (body != null)
                {
                    request.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
                }
                using HttpResponseMessage response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellation);
                status = (int)response.StatusCode;
                if (!response.IsSuccessStatusCode)
                {
                    throw new EmergencyFault(502, "issuer_request_failed_new_login_may_be_required");
                }
                if (response.StatusCode == System.Net.HttpStatusCode.NoContent)
                {
                    received = true;
                    return default;
                }
                using Stream stream = await response.Content.ReadAsStreamAsync(cancellation);
                using MemoryStream bytes = new MemoryStream();
                byte[] buffer = new byte[4096];
                int count;
                while ((count = await stream.ReadAsync(buffer, cancellation)) != 0)
                {
                    if (bytes.Length + count > 131072)
                    {
                        throw new EmergencyFault(502, "issuer_response_rejected");
                    }
                    bytes.Write(buffer, 0, count);
                }
                var parsed = StrictJson.Parse(new UTF8Encoding(false, true).GetString(bytes.ToArray()));
                received = true;
                return parsed;
            }
            finally { IssuerCallTrace.Record(method.Method, relative, status, timer.ElapsedMilliseconds, received); }
        }
    }
}
