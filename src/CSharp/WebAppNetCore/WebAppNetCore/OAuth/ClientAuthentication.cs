using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace WebAppNetCore.OAuth
{
    /// <summary>
    /// Adds the configured client authentication (TokenAuthnMethod) to a request for any endpoint that authenticates the client.
    /// Identify applies the configured method at the token, PAR, revocation, and introspection endpoints.
    /// </summary>
    public sealed class ClientAuthentication
    {
        public const string ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

        private readonly IConfiguration configuration;

        public ClientAuthentication(IConfiguration configuration)
        {
            this.configuration = configuration;
        }

        /// <summary>
        /// Adds the client authentication to the request. Returns the client assertion for private_key_jwt, and null otherwise.
        /// </summary>
        public string Apply(HttpRequestMessage request, IDictionary<string, string> parameters, OpenIdConnectConfiguration metadata)
        {
            switch (configuration.TokenAuthnMethod())
            {
                case "client_secret_post":
                    parameters["client_id"] = configuration.ClientId();
                    parameters["client_secret"] = configuration.ClientSecret();
                    return null;

                case "client_secret_basic":
                    var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Encode(configuration.ClientId())}:{Encode(configuration.ClientSecret())}"));
                    request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);
                    return null;

                default: // private_key_jwt
                    var clientAssertion = CreateClientAssertion(metadata);
                    parameters["client_assertion_type"] = ClientAssertionType;
                    parameters["client_assertion"] = clientAssertion;
                    parameters["client_id"] = configuration.ClientId();
                    return clientAssertion;
            }
        }

        private string CreateClientAssertion(OpenIdConnectConfiguration metadata)
        {
            using var cert = JwtAssertionSigningCertificate();
            if (cert == null || !cert.HasPrivateKey)
            {
                throw new OAuthClientException("Client certificate is not configured or does not have a private key for private_key_jwt authentication.");
            }

            // With the Identify rule clientAssertion.audience=issuer, aud must be the issuer as one JSON string, not an array.
            var audience = configuration.ClientAssertionAudience() == ClientAssertionAudience.Issuer
                ? metadata.Issuer
                : IdentifyMetadata.RequireEndpoint(metadata.TokenEndpoint, "token_endpoint");

            var now = DateTimeOffset.UtcNow;
            var claims = new Dictionary<string, object>
            {
                { "iss", configuration.ClientId() },
                { "sub", configuration.ClientId() },
                { "aud", audience },
                { "jti", Guid.NewGuid().ToString() }, // a new value for each assertion, because Identify rejects a replayed jti
                { "exp", now.AddMinutes(5).ToUnixTimeSeconds() },
                { "iat", now.ToUnixTimeSeconds() }
            };

            // Identify accepts RS256 to PS512, restricted per connection by the rule clientJwt.signingAlgorithms.
            var signingCredentials = new X509SigningCredentials(cert, configuration.ClientAssertionSigningAlgorithm());
            signingCredentials.Key.KeyId = Base64UrlEncoder.Encode(cert.GetCertHash());
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Claims = claims,
                SigningCredentials = signingCredentials
            };

            return new JsonWebTokenHandler().CreateToken(tokenDescriptor);
        }

        private X509Certificate2 JwtAssertionSigningCertificate()
        {
            // Load certificate from file (for demo only)
            var certPath = configuration.JwtAssertionSigningCertPath();
            var certPassword = configuration.JwtAssertionSigningCertPassword();
            if (!string.IsNullOrEmpty(certPath) && !string.IsNullOrEmpty(certPassword))
            {
                return X509CertificateLoader.LoadPkcs12FromFile(certPath, certPassword);
            }

            return null;
        }

        private static string Encode(string data)
        {
            if (string.IsNullOrEmpty(data))
            {
                return string.Empty;
            }
            // Escape spaces as '+'.
            return Uri.EscapeDataString(data).Replace("%20", "+");
        }
    }
}
