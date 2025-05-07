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

- Support sending a token request using a specified client authentication method like �client_secret_post" or "client_secret_basic".

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

- Edit "appsettings.json", change setting TokenAuthnMethod to "client_secret_post" or "client_secret_basic"


