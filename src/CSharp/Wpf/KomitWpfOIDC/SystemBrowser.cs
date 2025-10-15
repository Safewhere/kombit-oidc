using System.Diagnostics;
using System.Net;
using System.Text;
using IdentityModel.OidcClient.Browser;

namespace KomitWpfOIDC
{
    public class SystemBrowser : IBrowser
    {
        public async Task<BrowserResult> InvokeAsync(BrowserOptions options, CancellationToken cancellationToken = default)
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = options.StartUrl,
                UseShellExecute = true
            });

            string redirectURI = ConfigurationExtensions.LoopbackRedirect;

            var listener = new HttpListener();
            listener.Prefixes.Add(redirectURI);
            try
            {
                listener.Start();

                var ctxTask = listener.GetContextAsync();
                var done = await Task.WhenAny(ctxTask, Task.Delay(TimeSpan.FromMinutes(1), cancellationToken));
                if (done != ctxTask)
                {
                    return new BrowserResult { ResultType = BrowserResultType.Timeout, Error = "Timeout waiting for callback." };
                }

                var context = await ctxTask;
                var resultUrl = context.Request.Url!.ToString();

                var html = BuildHtml(context.Request);
                var buffer = Encoding.UTF8.GetBytes(html);
                context.Response.ContentLength64 = buffer.Length;
                await context.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                context.Response.OutputStream.Close();

                return new BrowserResult { ResultType = BrowserResultType.Success, Response = resultUrl };
            }
            catch (HttpListenerException ex) when (ex.ErrorCode == 5)
            {
                return new BrowserResult
                {
                    ResultType = BrowserResultType.HttpError,
                    Error = $"Access denied for {redirectURI}. If needed, run as admin:\nnetsh http add urlacl url={redirectURI} user={Environment.UserName}"
                };
            }
            catch (Exception ex)
            {
                return new BrowserResult { ResultType = BrowserResultType.UnknownError, Error = ex.ToString() };
            }
            finally
            {
                if (listener.IsListening) listener.Stop();
            }
        }
        public async Task<string?> WaitForCallbackAsync(string redirectUri, TimeSpan timeout)
        {
            using var listener = new HttpListener();
            listener.Prefixes.Add(ConfigurationExtensions.LoopbackRedirect);
            listener.Start();

            var ctxTask = listener.GetContextAsync();
            var done = await Task.WhenAny(ctxTask, Task.Delay(timeout));
            if (done != ctxTask) return null;

            var ctx = await ctxTask;
            var responseUrl = ctx.Request.Url!.ToString();

            var html = BuildHtml(ctx.Request);
            var buf = System.Text.Encoding.UTF8.GetBytes(html);
            ctx.Response.ContentType = "text/html; charset=utf-8";
            ctx.Response.ContentLength64 = buf.Length;
            await ctx.Response.OutputStream.WriteAsync(buf, 0, buf.Length);
            ctx.Response.OutputStream.Close();

            return responseUrl;
        }
        private static string BuildHtml(HttpListenerRequest req)
        {
            var q = req.QueryString;
            var error = q["error_description"];

            if (!string.IsNullOrEmpty(error))
            {
                return $@"
                <html><body style='font-family:sans-serif;background:#31407b;color:#fff;text-align:center;padding:40px'>
                  <h2 style='color:#ff6666'>Failed</h2>
                  <p>{WebUtility.HtmlEncode(error)}</p>
                </body></html>";
            }
            else
            {
                return @"
                <html><head><meta http-equiv='refresh' content='5;url=https://google.com'></head><body style='font-family:sans-serif;background:#31407b;color:#fff;text-align:center;padding:40px'>
                  <h2>OK</h2>
                  <p>You can close this window.</p>
                  <script>setTimeout(()=>window.close(),2000);</script>
                </body></html>";
            }
        }
    }

}
