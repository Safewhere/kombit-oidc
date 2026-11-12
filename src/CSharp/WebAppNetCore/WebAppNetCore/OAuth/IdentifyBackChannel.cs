using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace WebAppNetCore.OAuth
{
    /// <summary>
    /// The endpoints where Identify authenticates the client.
    /// </summary>
    public enum ClientAuthenticationEndpoint
    {
        PushedAuthorizationRequest,
        Token,
        Revocation,
        Introspection
    }

    /// <summary>
    /// The UserInfo endpoint of a request, and whether the request presents the client certificate.
    /// </summary>
    public sealed record UserInfoTarget(string Endpoint, bool SendsCertificate);

    /// <summary>
    /// Selects the endpoint and the HttpClient of the requests that authenticate the client, and of UserInfo. With mutual TLS
    /// (RFC 8705), these requests go to the mtls_endpoint_aliases of the discovery document (RFC 8705 section 5), over a connection
    /// that presents the client certificate. Without mutual TLS, they go to the normal endpoints.
    /// </summary>
    public sealed class IdentifyBackChannel
    {
        public const string MutualTlsEndpointAliases = "mtls_endpoint_aliases";
        public const string UserInfoEndpointName = "userinfo_endpoint";

        // The faults that send the request without the client certificate.
        private static readonly Dictionary<ClientAuthenticationEndpoint, Fault[]> FaultsWithoutCertificate = new()
        {
            [ClientAuthenticationEndpoint.PushedAuthorizationRequest] = new[] { Fault.ParWithoutClientAuthentication, Fault.MtlsParAtNormalEndpoint },
            [ClientAuthenticationEndpoint.Token] = new[] { Fault.RefreshWithoutClientAuthentication, Fault.MtlsTokenAtNormalEndpoint, Fault.MtlsRefreshAtNormalEndpoint },
            [ClientAuthenticationEndpoint.Revocation] = new[] { Fault.RevokeWithoutClientAuthentication },
            [ClientAuthenticationEndpoint.Introspection] = new[] { Fault.IntrospectWithoutClientAuthentication }
        };

        // The faults that send the request to the normal endpoint instead of its mTLS alias.
        private static readonly Dictionary<ClientAuthenticationEndpoint, Fault[]> FaultsAtNormalEndpoint = new()
        {
            [ClientAuthenticationEndpoint.PushedAuthorizationRequest] = new[] { Fault.MtlsParAtNormalEndpoint },
            [ClientAuthenticationEndpoint.Token] = new[] { Fault.MtlsTokenAtNormalEndpoint, Fault.MtlsRefreshAtNormalEndpoint },
            [ClientAuthenticationEndpoint.Revocation] = Array.Empty<Fault>(),
            [ClientAuthenticationEndpoint.Introspection] = Array.Empty<Fault>()
        };

        private static readonly Fault[] MutualTlsFaults =
        {
            Fault.MtlsParAtNormalEndpoint, Fault.MtlsTokenAtNormalEndpoint, Fault.MtlsRefreshAtNormalEndpoint, Fault.MtlsUserInfoAtNormalEndpoint
        };

        private readonly IHttpClientFactory httpClientFactory;
        private readonly IConfiguration configuration;
        private readonly MutualTlsClientCertificate clientCertificate;

        public IdentifyBackChannel(IHttpClientFactory httpClientFactory, IConfiguration configuration, MutualTlsClientCertificate clientCertificate)
        {
            this.httpClientFactory = httpClientFactory;
            this.configuration = configuration;
            this.clientCertificate = clientCertificate;
        }

        /// <summary>
        /// The URL of the endpoint: the mTLS alias with mutual TLS, otherwise the endpoint of the discovery document. With mutual TLS,
        /// a missing alias is an error; the sample never sends the request to the normal endpoint instead.
        /// </summary>
        public string Endpoint(OpenIdConnectConfiguration metadata, ClientAuthenticationEndpoint endpoint, Fault fault = Fault.None)
        {
            RequireMutualTlsForFault(fault);

            var name = MetadataName(endpoint);
            if (!configuration.UsesMutualTls() || FaultsAtNormalEndpoint[endpoint].Contains(fault))
            {
                return IdentifyMetadata.RequireEndpoint(NormalEndpoint(metadata, endpoint), name);
            }

            var alias = ReadMutualTlsEndpointAlias(metadata, name);
            if (string.IsNullOrEmpty(alias))
            {
                throw new OAuthClientException(string.Format(
                    "The discovery document has no {0} in {1}. With mutual TLS, the sample sends this request only to the mTLS endpoint alias.",
                    name, MutualTlsEndpointAliases));
            }

            return alias;
        }

        /// <summary>
        /// The UserInfo endpoint. With mutual TLS, Identify binds the access tokens to the client certificate, and UserInfo accepts such a
        /// token only with the certificate (RFC 8705 section 3). So the request goes to the UserInfo alias of mtls_endpoint_aliases with
        /// the certificate. When the discovery document has no UserInfo alias, the request goes to userinfo_endpoint without the
        /// certificate, as RFC 8705 section 5 says. The fault MtlsUserInfoAtNormalEndpoint sends it there too.
        /// </summary>
        public UserInfoTarget UserInfoEndpoint(OpenIdConnectConfiguration metadata, Fault fault = Fault.None)
        {
            RequireMutualTlsForFault(fault);
            var alias = configuration.UsesMutualTls() && fault != Fault.MtlsUserInfoAtNormalEndpoint
                ? ReadMutualTlsEndpointAlias(metadata, UserInfoEndpointName)
                : null;
            return string.IsNullOrEmpty(alias) ? new UserInfoTarget(metadata.UserInfoEndpoint, false) : new UserInfoTarget(alias, true);
        }

        /// <summary>
        /// Whether the request presents the client certificate: with mutual TLS, except for the faults that leave it out.
        /// </summary>
        public bool SendsCertificate(ClientAuthenticationEndpoint endpoint, Fault fault = Fault.None)
        {
            return configuration.UsesMutualTls() && !FaultsWithoutCertificate[endpoint].Contains(fault);
        }

        /// <summary>
        /// Sends the request, with the client certificate when SendsCertificate is true. With mutual TLS, the protocol trace shows the
        /// x5t#S256 value of the certificate, or that the request had no certificate.
        /// </summary>
        public Task<HttpResponseMessage> SendAsync(ClientAuthenticationEndpoint endpoint, HttpRequestMessage request, Fault fault, CancellationToken cancellationToken)
        {
            return SendAsync(request, SendsCertificate(endpoint, fault), cancellationToken);
        }

        /// <summary>
        /// Sends the request, with the client certificate when sendsCertificate is true. With mutual TLS, the protocol trace shows the
        /// x5t#S256 value of the certificate, or that the request had no certificate.
        /// </summary>
        public Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, bool sendsCertificate, CancellationToken cancellationToken)
        {
            if (configuration.UsesMutualTls())
            {
                request.Options.Set(ProtocolTrace.ClientCertificateKey, sendsCertificate ? "x5t#S256 " + clientCertificate.Thumbprint : "(none)");
            }

            var client = httpClientFactory.CreateClient(sendsCertificate ? IdentifyHttpClient.MutualTlsName : IdentifyHttpClient.Name);
            return client.SendAsync(request, cancellationToken);
        }

        /// <summary>
        /// With mutual TLS, Identify binds the access token to the certificate of the token request (RFC 8705 section 3). The method
        /// throws when the cnf.x5t#S256 claim of the access token is not the thumbprint of the client certificate. Without mutual TLS,
        /// it does nothing.
        /// </summary>
        public void CheckCertificateBinding(string accessToken)
        {
            if (!configuration.UsesMutualTls())
            {
                return;
            }

            var bound = AccessTokenInspector.ReadCertificateThumbprint(accessToken);
            if (!string.Equals(bound, clientCertificate.Thumbprint, StringComparison.Ordinal))
            {
                throw new OAuthClientException(string.Format(
                    "The access token is not bound to the client certificate (RFC 8705 section 3): its cnf.x5t#S256 is '{0}', and the certificate has '{1}'.",
                    bound ?? "(none)", clientCertificate.Thumbprint));
            }
        }

        /// <summary>
        /// Reads an endpoint from mtls_endpoint_aliases. The library keeps unknown members of the discovery document in AdditionalData.
        /// </summary>
        public static string ReadMutualTlsEndpointAlias(OpenIdConnectConfiguration metadata, string name)
        {
            if (!metadata.AdditionalData.TryGetValue(MutualTlsEndpointAliases, out var aliases) || aliases == null)
            {
                return null;
            }

            switch (aliases)
            {
                case JsonElement element:
                    return ReadMutualTlsEndpointAlias(element, name);
                case IDictionary<string, object> dictionary:
                    return dictionary.TryGetValue(name, out var item) ? item as string : null;
                case string json:
                    using (var document = JsonDocument.Parse(json))
                    {
                        return ReadMutualTlsEndpointAlias(document.RootElement, name);
                    }
                default:
                    return null;
            }
        }

        private static string ReadMutualTlsEndpointAlias(JsonElement element, string name)
        {
            return element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : null;
        }

        private void RequireMutualTlsForFault(Fault fault)
        {
            if (MutualTlsFaults.Contains(fault) && !configuration.UsesMutualTls())
            {
                throw new OAuthClientException("The fault " + fault + " needs mutual TLS: TokenAuthnMethod tls_client_auth or self_signed_tls_client_auth, "
                    + "or MutualTls:UseEndpointAliases. The request was not sent.");
            }
        }

        private static string MetadataName(ClientAuthenticationEndpoint endpoint)
        {
            return endpoint switch
            {
                ClientAuthenticationEndpoint.PushedAuthorizationRequest => "pushed_authorization_request_endpoint",
                ClientAuthenticationEndpoint.Token => "token_endpoint",
                ClientAuthenticationEndpoint.Revocation => "revocation_endpoint",
                ClientAuthenticationEndpoint.Introspection => "introspection_endpoint",
                _ => throw new ArgumentOutOfRangeException(nameof(endpoint), endpoint, null)
            };
        }

        private static string NormalEndpoint(OpenIdConnectConfiguration metadata, ClientAuthenticationEndpoint endpoint)
        {
            return endpoint switch
            {
                ClientAuthenticationEndpoint.PushedAuthorizationRequest => metadata.PushedAuthorizationRequestEndpoint,
                ClientAuthenticationEndpoint.Token => metadata.TokenEndpoint,
                ClientAuthenticationEndpoint.Revocation => metadata.RevocationEndpoint,
                ClientAuthenticationEndpoint.Introspection => metadata.IntrospectionEndpoint,
                _ => throw new ArgumentOutOfRangeException(nameof(endpoint), endpoint, null)
            };
        }
    }
}
