# Introduction

This project contains sample code for OAuth2 and OpenID Connect in a WPF desktop application. The application is built for demonstration and testing purposes, particularly within KOMBIT projects.

To run this sample, you will need to install [.NET 10.0 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) or later.

By default, all the necessary configurations for running this application are already set up for one-click execution in Visual Studio. These configurations are placed in the `App.config` file.

This application supports the following features:

- Uses the Authorization Code Flow with PKCE for user authentication.
- Supports sending an authorization request with a desired assurance level and a specified max_age.
- Supports sending an authorization request to re-authenticate the user, perform passive authentication, or force authentication.
- Supports sending an authorization request using POST or GET method.
- Supports custom URI scheme (`wpfoidc://`) for OAuth redirects.
- Supports HTTP loopback redirect for development scenarios.
- Single instance application with inter-process communication (IPC) for handling callbacks.
- ID Token and Access Token visualization with JWT decoding.

# Configurations

## App.config Settings

The application is configured via the `App.config` file:

```xml
<appSettings>
  <add key="ClaimsIssuer" value="https://kombitdev.safewhere.local/runtime/oauth2" />
  <add key="ClientId" value="wpf-application" />
  <add key="Scope" value="openid" />
  <add key="Port" value="44038" />
  <add key="AuthorizationEndpointMethod" value="GET" />
  <add key="UseCustomScheme" value="true" />
</appSettings>
```

### Configuration Parameters

| Key | Description | Example |
|-----|-------------|---------|
| `ClaimsIssuer` | The base URL of your OIDC provider | `https://kombitdev.safewhere.local/runtime/oauth2` |
| `ClientId` | The OAuth client ID registered with the OIDC provider | `wpf-application` |
| `Scope` | Space-separated list of OAuth scopes | `openid` |
| `Port` | Port number for HTTP loopback redirect (when UseCustomScheme=false) | `44038` |
| `AuthorizationEndpointMethod` | HTTP method for authorization endpoint | `GET` or `POST` |
| `UseCustomScheme` | Enable custom URI scheme (`wpfoidc://`) instead of localhost | `true` or `false` |

## Custom URI Scheme vs HTTP Loopback

### Use Custom URI Scheme (wpfoidc://)

- Edit `App.config` and set `UseCustomScheme` to `true`
- The application will automatically register the `wpfoidc://` protocol handler in Windows Registry
- Redirect URI: `wpfoidc://callback`
- **Benefits**: No port reservation needed, more secure, better user experience
- **Requirements**: Windows 10/11

### Use HTTP Loopback (localhost)

- Edit `App.config` and set `UseCustomScheme` to `false`
- Redirect URI: `http://127.0.0.1:{Port}/`
- If you get "Access denied" errors, run this command as administrator:
  ```cmd
  netsh http add urlacl url=http://127.0.0.1:44038/ user=YOUR_USERNAME
  ```

## Support both GET and POST for Authorization Request

- Edit `App.config` and change the setting `AuthorizationEndpointMethod` to `GET` or `POST`

## Provisioning Data

When configuring the OIDC connection in your identity provider, use the appropriate redirect URI:

- **Custom Scheme**: `wpfoidc://callback`
- **HTTP Loopback**: `http://127.0.0.1:44038/` (or your configured port)

# Running the Application

## Using Visual Studio

1. Open the solution in Visual Studio 2022
2. Restore NuGet packages
3. Build the solution (Ctrl+Shift+B)
4. Run the application (F5)

## Using .NET CLI

```bash
dotnet restore
dotnet build
dotnet run
```

# Features

## Authentication Flow

1. Configure the `App.config` with your OIDC provider settings
2. Launch the application
3. (Optional) Select an **Assurance Level** from the dropdown
4. (Optional) Enter a **max_age** value (in seconds)
5. Click **LOGIN** to initiate authentication
6. Complete authentication in your browser
7. View authenticated session and tokens

## Re-authentication Options

After login, you can test different authentication scenarios:

- **Re-authenticate**: Start a new authentication flow with current parameters
- **Force Authentication**: Require user to re-enter credentials (`prompt=login`)
- **Passive Authentication**: Attempt silent authentication (`prompt=none`)

## Token Inspection

- **ID Token**: View raw token, header, and payload (decoded JWT)
- **Access Token**: View raw token, header, and payload (decoded JWT)

## Logout

The application automatically performs logout when closing, which includes:
- Ending the session with the OIDC provider
- Clearing local token storage
- Resetting the UI state

# Architecture

## Key Components

| Component | Description |
|-----------|-------------|
| `MainWindow.xaml/cs` | Main UI and authentication logic |
| `ConfigurationExtensions.cs` | Configuration and OIDC discovery |
| `CustomSchemeBrowser.cs` | Custom URI scheme implementation |
| `SystemBrowser.cs` | HTTP loopback implementation |
| `CustomSchemeRegistrar.cs` | Windows Registry management |
| `IpcCallbackHandler.cs` | Inter-process communication |
| `OpenIdConnectHelper.cs` | PKCE, JWT parsing, URL generation |
| `TokenInfo.cs` | Token storage |

## PKCE Flow

The application implements OAuth 2.0 PKCE (Proof Key for Code Exchange):

1. Generate random code verifier (43 characters)
2. Create code challenge (SHA-256 hash of verifier)
3. Send code challenge in authorization request
4. Send code verifier in token request for validation

# Troubleshooting

## Custom Scheme Not Working

1. Check if protocol is registered: `HKEY_CURRENT_USER\Software\Classes\wpfoidc`
2. Restart the application
3. Try running as administrator
4. Switch to HTTP loopback: set `UseCustomScheme=false`

## HTTP Loopback Access Denied

1. Run as administrator, or
2. Grant URL reservation:
   ```cmd
   netsh http add urlacl url=http://127.0.0.1:44038/ user=YOUR_USERNAME
   ```

## Token Validation Failed

1. Verify `ClaimsIssuer` matches the `iss` claim
2. Verify `ClientId` matches the `aud` claim
3. Check system clock synchronization
4. Ensure JWKS endpoint is accessible

## Discovery Error

1. Verify `ClaimsIssuer` URL is correct
2. Check network accessibility
3. Verify HTTPS certificate
4. Test discovery endpoint: `{ClaimsIssuer}/.well-known/openid-configuration`
