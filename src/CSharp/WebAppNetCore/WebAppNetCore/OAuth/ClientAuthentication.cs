using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
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
        /// Give clientId to authenticate as another client with the credentials of this one, for the faults RedeemAsOtherClient
        /// and RefreshAsOtherClient.
        /// </summary>
        public string Apply(HttpRequestMessage request, IDictionary<string, string> parameters, OpenIdConnectConfiguration metadata, Fault fault = Fault.None, string clientId = null)
        {
            clientId ??= configuration.ClientId();
            switch (configuration.TokenAuthnMethod())
            {
                case "client_secret_post":
                    parameters["client_id"] = clientId;
                    parameters["client_secret"] = configuration.ClientSecret();
                    return null;

                case "client_secret_basic":
                    var credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Encode(clientId)}:{Encode(configuration.ClientSecret())}"));
                    request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);
                    return null;

                default: // private_key_jwt
                    var clientAssertion = CreateClientAssertion(metadata, fault, clientId);
                    parameters["client_assertion_type"] = ClientAssertionType;
                    parameters["client_assertion"] = clientAssertion;
                    parameters["client_id"] = clientId;
                    return clientAssertion;
            }
        }

        private string CreateClientAssertion(OpenIdConnectConfiguration metadata, Fault fault, string clientId)
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

            var issuedAt = fault switch
            {
                Fault.AssertionFutureIat => DateTimeOffset.UtcNow.AddSeconds(120),
                Fault.AssertionExpired => DateTimeOffset.UtcNow.AddSeconds(-120),
                _ => DateTimeOffset.UtcNow
            };
            var expiresAt = fault == Fault.AssertionExpired ? DateTimeOffset.UtcNow.AddSeconds(-60) : issuedAt.AddMinutes(5);
            var claims = new Dictionary<string, object>
            {
                { "iss", fault == Fault.AssertionIssuerNotClient ? configuration.OtherClientId() : clientId },
                { "sub", clientId },
                { "aud", fault == Fault.AssertionAudienceArray ? new[] { audience } : (object)audience },
                { "jti", Guid.NewGuid().ToString() }, // a new value for each assertion, because Identify rejects a replayed jti
                { "exp", expiresAt.ToUnixTimeSeconds() },
                { "iat", issuedAt.ToUnixTimeSeconds() }
            };

            // The kid of the client key, also for the forged assertions, so that Identify finds the key that must verify them.
            var keyId = Base64UrlEncoder.Encode(cert.GetCertHash());
            switch (fault)
            {
                case Fault.AssertionAlgNone:
                    return FaultJwt.Unsigned(new Dictionary<string, object> { ["typ"] = "JWT", ["kid"] = keyId }, claims);

                case Fault.AssertionHmacWithClientSecret:
                    return FaultJwt.Hmac(
                        new Dictionary<string, object> { ["typ"] = "JWT" }, claims, Encoding.UTF8.GetBytes(configuration.ClientSecret() ?? string.Empty));

                case Fault.AssertionWithoutExp:
                    claims.Remove("exp");
                    break;
            }

            // Identify accepts RS256 to PS512, restricted per connection by the rule clientJwt.signingAlgorithms.
            using var otherKey = fault == Fault.AssertionSignedByOtherKey ? RSA.Create(2048) : null;
            var signingCredentials = otherKey == null
                ? new X509SigningCredentials(cert, configuration.ClientAssertionSigningAlgorithm())
                : new SigningCredentials(new RsaSecurityKey(otherKey), configuration.ClientAssertionSigningAlgorithm());
            signingCredentials.Key.KeyId = keyId;
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Claims = claims,
                SigningCredentials = signingCredentials
            };

            // Without default times for the faults, so that AssertionWithoutExp has no exp and AssertionExpired gets no nbf after its exp.
            var defaultTimes = fault != Fault.AssertionWithoutExp && fault != Fault.AssertionExpired;
            return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = defaultTimes }.CreateToken(tokenDescriptor);
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
