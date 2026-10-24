using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WebAppNetCore.EmergencyCredential
{
    public static class StrictJson
    {
        public static JsonElement Parse(string text)
        {
            if (text == null || Encoding.UTF8.GetByteCount(text) > 131072)
            {
                throw Bad();
            }
            using JsonDocument document = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 24 });
            Check(document.RootElement);
            return document.RootElement.Clone();
        }
        private static void Check(JsonElement value)
        {
            if (value.ValueKind == JsonValueKind.Object)
            {
                HashSet<string> names = new HashSet<string>(StringComparer.Ordinal);
                foreach (JsonProperty property in value.EnumerateObject())
                {
                    if (!names.Add(property.Name) || property.Name.StartsWith("$", StringComparison.Ordinal))
                    {
                        throw Bad();
                    }
                    Check(property.Value);
                }
            }
            else if (value.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement item in value.EnumerateArray())
                {
                    Check(item);
                }
            }
        }
        public static void Members(JsonElement value, params string[] allowed)
        {
            if (value.ValueKind != JsonValueKind.Object || value.EnumerateObject().Any(property => !allowed.Contains(property.Name, StringComparer.Ordinal)))
            {
                throw Bad();
            }
        }
        public static string Text(JsonElement value, string name, int maximum = 1024)
        {
            if (!value.TryGetProperty(name, out JsonElement field) || field.ValueKind != JsonValueKind.String)
            {
                throw Bad();
            }
            string text = field.GetString();
            if (string.IsNullOrEmpty(text) || text.Length > maximum || text.Any(char.IsControl))
            {
                throw Bad();
            }
            return text;
        }
        public static long Integer(JsonElement value, string name)
        {
            if (!value.TryGetProperty(name, out JsonElement field) || !field.TryGetInt64(out long result))
            {
                throw Bad();
            }
            return result;
        }
        public static byte[] Bytes(string text, int maximum = 65536)
        {
            if (string.IsNullOrEmpty(text) || text.Length > maximum * 2 || text.Any(c => !(char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_')))
            {
                throw Bad();
            }
            byte[] bytes = Convert.FromBase64String(text.Replace('-', '+').Replace('_', '/') + new string('=', (4 - text.Length % 4) % 4));
            if (bytes.Length > maximum || Encode(bytes) != text)
            {
                throw Bad();
            }
            return bytes;
        }
        public static string Encode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        public static string Id() => Encode(RandomNumberGenerator.GetBytes(32));
        public static string Hash(string text) => Encode(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
        public static bool Same(string first, string second) => first != null && second != null
            && CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(first)), SHA256.HashData(Encoding.UTF8.GetBytes(second)));
        public static EmergencyFault Bad() => new EmergencyFault(400, "invalid_request");
    }
}
