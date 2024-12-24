# Introduction
This project contains sample code for OAuth2, OpenId Connect using Asp.Net core.

To run this sample, you will need to install [dotnet core runtime 2.1.5](https://www.microsoft.com/net/download/thank-you/dotnet-runtime-2.1.5-windows-hosting-bundle-installer).

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

++ Identify configuration
-- Not necessary

## Enable post logout request
Even though a RP-initiated logout request must be made via GET, Identity version 5.6 is extended to either accept POST logout request to allow flowing large logout payloads. 

++ Client configuration
- Edit "appsettings.json", change setting EnablePostLogout to "True". This option will enable button "PostLogout" as following image
![post logout](Images/postlogout.png)

++ Identify configuration
-- Change "OpenID Connect logout redirect URL" to "https://localhost:44307/Account/SignedOutCallback"