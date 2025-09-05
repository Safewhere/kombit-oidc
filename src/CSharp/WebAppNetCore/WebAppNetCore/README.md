# Introduction
This project contains sample code for OAuth2, OpenId Connect using Asp.Net core. The application is built for demonstration and testing purposes, particularly within KOMBIT projects.

To run this sample, you will need to install [ASP.NET Core Runtime 8](https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/runtime-aspnetcore-8.0.15-windows-hosting-bundle-installer).

By default, all the necessary configurations for running this application are already set up for one-click execution in Visual Studio. These configurations are placed in the "appsettings.json" file . This application supports the following features:

- Use the Authorization Code Flow with PKCE for user authentication.

- Support sending an authorization request with a desired assurance level and a specified max_age.

- Support sending an authorization request to re-authenticate user, do passive authentication or force authentication.

- Session management.

- Support sending a logout request using POST or GET method.

- Support sending an authorization request using POST or GET method

- Support sending a token request using a specified client authentication method like "client_secret_post", "client_secret_basic" or "private_key_jwt".

- Support back-channel logout. The URL at /back-channel-logout

- Support front-channel logout. The URL at /front-channel-logout

- Support Id token encryption.

# Configurations

## Enable openid connect session management

++ Client configuration
- Edit "appsettings.json", change setting EnableSessionManagement to "True"

++ Provisioning data
- When the EnableSessionManagement is set to "True", the /Account/ReauthenticationCallback endpoint should be added into the OIDCMetadata's redirect_uris.

## Enable post logout request
Even though an RP-initiated logout request must be made via GET, the implementation has been extended to also accept POST logout requests to support larger logout payloads. 

++ Client configuration
- Edit "appsettings.json", change setting EnablePostLogout to "True". This option will enable button "PostLogout" as following image
![post logout](Images/postlogout.png)

- Provisioning data

For both GET and POST logout request, the /Account/SignedOutCallback endpoint should be set to OIDCMetadata's post_logout_redirect_uri.

## Support both GET and POST for Authorize request

- Edit "appsettings.json", change setting AuthorizationEndpointMethod to "GET" or "POST"

## Support configurable Token Authentication method

- Edit "appsettings.json", change setting TokenAuthnMethod to "client_secret_post", "client_secret_basic" or "private_key_jwt". 

## Private Key JWT client authentication
- When using the "private_key_jwt", you must provides the jwks or jwks_uri for the Identify OAuth/OIDC connection.
- You also need to provide the certificate to sign the client_assertion by configurating these tow settings in "appsettings.json":
  - JwtAssertionSigningCertPath
  - JwtAssertionSigningCertPassword

## Id token encryption

To enable Id token encryption, you need to configure the following settings in "appsettings.json":
- IdTokenDecryptionCertPath
- IdTokenDecryptionCertPassword

this certificate is used to decrypt the encrypted Id token received from the identity provider.

Note that Identify encrypt the Id token by using the public key from the jwks or jwks_uri configured in the Identify OAuth/OIDC connection.
So the jwks or jwks_uri must contains the public certificate which corresponds to the above configured Id token decryption certificate.

## Back-channel & Front-channel logout

When enabling back-channel or front-channel logout on the Identify's OIDC connection, you must disable the EnableSessionManagement by setting it to "false".
