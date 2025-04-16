# Introduction
This project contains sample code for OAuth2, OpenId Connect using Asp.Net core.

To run this sample, you will need to install [ASP.NET Core Runtime 8](https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/runtime-aspnetcore-8.0.15-windows-hosting-bundle-installer).

# How to run the application
By default, all the necessary configurations for running this application is already setup for single click on visual studio. It is placed on "appsettings.json" and can be download on the corresponding client's implementation tab. 
With the default settings, this application provides demonstration for following criteria
- It is using openid connect and code flow
- It's able to authenticate user and allow user to edit user profile

# Advanced settings
There are some more advanced test cases which can be enabled by simple configurations as following

## Enable openid connect session management

++ Client configuration
- Edit "appsettings.json", change setting EnableSessionManagement to "True"

++ Provisioning data
- When the EnableSessionManagement is set to "True", the /Account/ReauthenticationCallback endpoint should be added into the OIDCMetadata's redirect_uris.

## Enable post logout request
Even though a RP-initiated logout request must be made via GET, Identity version 5.6 is extended to either accept POST logout request to allow flowing large logout payloads. 

++ Client configuration
- Edit "appsettings.json", change setting EnablePostLogout to "True". This option will enable button "PostLogout" as following image
![post logout](Images/postlogout.png)

- Provisioning data

For both GET and POST logout request, the /Account/SignedOutCallback endpoint should be set to OIDCMetadata's post_logout_redirect_uri.

## Support both GET and POST for Authorize request

- Edit "appsettings.json", change setting AuthorizationEndpointMethod to "GET" or "POST"

## Support configurable Token Authentication method

- Edit "appsettings.json", change setting TokenAuthnMethod to "client_secret_post" or "client_secret_basic"

## Turn on/off for Use PKCE

- Edit "appsettings.json", change setting UsePKCE to "true" or "false"

# Notes

Note that this example is not a production ready code. It is only for demonstration purpose. It is developed for KOMBIT testing so its features include some built-in supports:

- Support for authentication with Assurance Level & max_age
- Support Re-authentication, Force Authentication and Passive Authentication

