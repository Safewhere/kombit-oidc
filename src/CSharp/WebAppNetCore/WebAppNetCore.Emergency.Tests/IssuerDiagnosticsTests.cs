using System;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using WebAppNetCore.EmergencyCredential;
namespace WebAppNetCore.Emergency.Tests
{
    [TestClass]
    public class IssuerDiagnosticsTests
    {
        private sealed class Reply : HttpMessageHandler
        {
            public int Status;
            public string Body;
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellation)
            {
                if (Status == 0)
                    throw new HttpRequestException("private transport detail");
                return Task.FromResult(new HttpResponseMessage((HttpStatusCode)Status) { Content = new StringContent(Body) });
            }
        }
        [DataTestMethod]
        [DataRow(201, "{\"emergency_credential\":\"private-token\"}", "Encrypted emergency credential received")]
        [DataRow(204, "", "Operation acknowledged")]
        [DataRow(403, "private issuer error", "unsuccessful HTTP status")]
        [DataRow(200, "invalid private response", "body could not be accepted")]
        [DataRow(0, "", "No HTTP response")]
        public async Task Calls_RecordActualStatusWithoutSensitiveData(int status, string body, string expected)
        {
            string variable = "EMERGENCY_TRACE_TEST_" + Guid.NewGuid().ToString("N");
            Environment.SetEnvironmentVariable(variable, new string('k', 40));
            try
            {
                using (var trace = new IssuerCallTrace())
                using (var http = new HttpClient(new Reply { Status = status, Body = body }))
                {
                    var client = new IssuerClient(new EmergencyOptions { IssuerBaseUrl = "https://issuer.invalid/runtime/", ApiKeyEnvironmentVariable = variable }, http);
                    bool failed = false;
                    try
                    {
                        await client.SendAsync(HttpMethod.Post, "emergency/enrollments/private-binding/complete", new
                        {
                            secret = "private-body"
                        }, CancellationToken.None);
                    }
                    catch (Exception) { failed = true; }
                    Assert.AreEqual(status == 0 || status == 403 || status == 200, failed);
                    string json = JsonSerializer.Serialize(trace.Snapshot());
                    StringAssert.Contains(json, expected);
                    StringAssert.Contains(json, status == 0 ? "\"status\":null" : "\"status\":" + status);
                    Assert.IsFalse(json.Contains("private"));
                    Assert.IsFalse(json.Contains(new string('k', 40)));
                    Assert.AreEqual(1, trace.Snapshot().Length);
                }
            }
            finally { Environment.SetEnvironmentVariable(variable, null); }
        }
        [TestMethod]
        public async Task Scopes_IsolateConcurrentRequestsAndBoundHistory()
        {
            Func<int, Task<string>> run = async status =>
            {
                using (var trace = new IssuerCallTrace())
                {
                    await Task.Yield();
                    for (int i = 0; i < 12; i++)
                        IssuerCallTrace.Record("POST", "emergency/enrollments/private-id/complete?secret=private", status, 1, true);
                    Assert.AreEqual(8, trace.Snapshot().Length);
                    return JsonSerializer.Serialize(trace.Snapshot());
                }
            };
            string[] results = await Task.WhenAll(run(201), run(202));
            StringAssert.Contains(results[0], "\"status\":201");
            Assert.IsFalse(results[0].Contains("202"));
            StringAssert.Contains(results[1], "\"status\":202");
            Assert.IsFalse(results[1].Contains("201"));
            Assert.IsFalse(results[0].Contains("private"));
            using (var empty = new IssuerCallTrace())
                Assert.AreEqual(0, empty.Snapshot().Length);
        }
    }
}
