using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace WebAppNetCore.OAuth
{
    /// <summary>
    /// The discovery document of Identify (FAPI 2.0 section 5.3.3.1 item 9). It comes from the same configuration manager as the
    /// OpenID Connect handler uses, so the handler and the sample always agree on the endpoints.
    /// </summary>
    public sealed class IdentifyMetadata
    {
        private readonly IOptionsMonitor<OpenIdConnectOptions> optionsMonitor;
        private readonly IConfiguration configuration;

        public IdentifyMetadata(IOptionsMonitor<OpenIdConnectOptions> optionsMonitor, IConfiguration configuration)
        {
            this.optionsMonitor = optionsMonitor;
            this.configuration = configuration;
        }

        /// <summary>
        /// Gets the discovery document and checks that its issuer is the configured issuer (FAPI 2.0 section 5.3.3.1 item 11).
        /// </summary>
        public async Task<OpenIdConnectConfiguration> GetAsync(CancellationToken cancellationToken)
        {
            var options = optionsMonitor.Get(OpenIdConnectDefaults.AuthenticationScheme);
            var metadata = await options.ConfigurationManager.GetConfigurationAsync(cancellationToken);

            // ClaimsIssuer is configured without a trailing slash.
            if (!string.Equals(metadata.Issuer?.TrimEnd('/'), configuration.ClaimsIssuer(), StringComparison.Ordinal))
            {
                throw new OAuthClientException(string.Format(
                    "The issuer '{0}' in the discovery document differs from the configured issuer '{1}'.", metadata.Issuer, configuration.ClaimsIssuer()));
            }

            return metadata;
        }

        public static string RequireEndpoint(string endpoint, string metadataName)
        {
            if (string.IsNullOrEmpty(endpoint))
            {
                throw new OAuthClientException(string.Format("The discovery document has no {0}.", metadataName));
            }

            return endpoint;
        }
    }
}
