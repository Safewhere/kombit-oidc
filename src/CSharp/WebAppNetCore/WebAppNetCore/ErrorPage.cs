using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.Extensions.DependencyInjection;
using WebAppNetCore.OAuth;

namespace WebAppNetCore
{
    /// <summary>
    /// Shows a sign-in or protocol error on /Home/Error. The message goes through TempData, not through the URL.
    /// </summary>
    public static class ErrorPage
    {
        public const string MessageKey = "RemoteError";
        private const int MaximumMessageLength = 2000;

        public static void Redirect(HttpContext httpContext, string message)
        {
            var tempData = httpContext.RequestServices.GetRequiredService<ITempDataDictionaryFactory>().GetTempData(httpContext);
            tempData[MessageKey] = message.Length > MaximumMessageLength ? message.Substring(0, MaximumMessageLength) : message;
            tempData.Save();
            httpContext.Response.Redirect("/Home/Error");
        }

        /// <summary>
        /// Describes a failure with the messages of the exception and its inner exceptions. An OAuthClientException ends the chain,
        /// because its message is complete.
        /// </summary>
        public static string Describe(Exception exception)
        {
            var messages = new List<string>();
            for (var current = exception; current != null; current = current.InnerException)
            {
                if (!messages.Contains(current.Message))
                {
                    messages.Add(current.Message);
                }

                if (current is OAuthClientException)
                {
                    break;
                }
            }

            return string.Join(" ", messages.Where(m => !string.IsNullOrEmpty(m)));
        }
    }
}
