using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using WebAppNetCore.EmergencyCredential;
namespace WebAppNetCore.Emergency.Tests
{
    [TestClass]
    public class EmergencyDiagnosticsTests
    {
        private sealed class Sink : ILoggerFactory, ILogger
        {
            public readonly List<string> Entries = new List<string>();
            public bool Fail;
            public ILogger CreateLogger(string category) => this;
            public void AddProvider(ILoggerProvider provider) { }
            public void Dispose() { }
            public IDisposable BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel level) => true;
            public void Log<TState>(LogLevel level, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
            {
                if (Fail) throw new InvalidOperationException("logger failed");
                Assert.IsNull(exception); Entries.Add(formatter(state, exception));
            }
        }
        [TestMethod]
        public void Logs_CorrelateStagesAndExcludeSensitiveInputs()
        {
            var sink = new Sink(); using var services = new ServiceCollection().AddSingleton<ILoggerFactory>(sink).BuildServiceProvider();
            var context = new DefaultHttpContext { RequestServices = services };
            context.Request.Path = "/emergency/keys/private-binding/remove";
            context.Request.QueryString = new QueryString("?secret=private-query");
            context.Request.Headers.Cookie = "session=private-cookie";
            var failure = new InvalidOperationException("private-message", new Exception("private-inner"));
            failure.Data["token"] = "private-token";
            EmergencyDiagnostics.Write(context, "request_started");
            EmergencyDiagnostics.Write(context, "action_failed", 503, failure);
            EmergencyDiagnostics.Write(context, "request_completed", 503, elapsedMilliseconds: 42);
            var entries = sink.Entries.Select(text => JsonDocument.Parse(text).RootElement.Clone()).ToArray();
            Assert.AreEqual(3, entries.Length);
            string reference = entries[0].GetProperty("reference_id").GetString();
            Assert.IsTrue(Guid.TryParseExact(reference, "N", out _));
            Assert.IsTrue(entries.All(e => e.GetProperty("reference_id").GetString() == reference));
            Assert.AreEqual(reference, context.Response.Headers["X-Emergency-Reference"].ToString());
            Assert.AreEqual("/emergency/keys/{id}/remove", entries[1].GetProperty("endpoint").GetString());
            Assert.AreEqual(2, entries[1].GetProperty("exceptions").GetArrayLength());
            Assert.AreEqual(42, entries[2].GetProperty("elapsed_ms").GetInt32());
            Assert.IsFalse(string.Join("", sink.Entries).Contains("private"));
            Assert.AreNotEqual(reference, EmergencyDiagnostics.Reference(new DefaultHttpContext()));
        }
        [TestMethod]
        public void LoggingFailure_DoesNotEscapeIntoAuthentication()
        {
            var sink = new Sink { Fail = true }; using var services = new ServiceCollection().AddSingleton<ILoggerFactory>(sink).BuildServiceProvider();
            EmergencyDiagnostics.Write(new DefaultHttpContext { RequestServices = services }, "request_completed");
        }
    }
}
