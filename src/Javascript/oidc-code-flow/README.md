# Safewhere Identify - OIDC Code Flow Sample

This is a Single Page Application (SPA) sample demonstrating how an SPA can negotiate tokens from the Identify OIDC service using the **code flow grant type**.  

The application is built using the [`oidc-client`](https://www.npmjs.com/package/oidc-client) npm package.  

---

## Configuration  

### Client Configuration  

All settings are stored in the `.env` file as follows:

- **`VITE_OAUTH_AUTHORITY`**: The URL of the OIDC/OAuth2 provider (e.g., `https://your-identity-provider.com/oauth2`).
- **`VITE_OAUTH_CLIENT_ID`**: The unique client identifier for your application, as registered with the OIDC/OAuth2 provider.
- **`VITE_OAUTH_SCOPE`**: The scope requested from the OIDC/OAuth2 provider (e.g., `openid`, default is `'openid'`).

#### Production deployment 

Assuming the SPA is deployed at `https://spa-oidc.safewhere.local` and the Identify OAuth service is at `https://develop.safewhere.local/runtime/`, the settings would look like this:  

- **`VITE_OAUTH_AUTHORITY`**: https://develop.safewhere.local/runtime/oauth2 
- **`VITE_OAUTH_CLIENT_ID`**: *(The client ID for the application as set up in Identify)*  
- **`VITE_OAUTH_SCOPE`**: `openid` *(must include the `openid` scope)*  

For production, you need to build the SPA and deploy the output in the `dist` folder to your hosting environment.  

1. Open a command prompt.  
2. Navigate to the `oidc-code-flow` folder.  
3. Run the following command to build the application:
    ```bash
    npm run build
    ```
    This will generate the production build files in the dist folder.
4. Deploy the contents of the dist folder to your web server or hosting service.

#### Local development  

If you're running the SPA in a Node.js development environment, you can use the built-in self-hosting.  

1. Open a command prompt.  
2. Navigate to the `oidc-code-flow` folder.  
3. Run the following command to start the web server:  

   ``` bash
   npm run dev
   ```

This will start the server at https://localhost:5173. The configuration settings will remain the same as those for https://spa-oidc.safewhere.local.

### Identify Configuration

The following configuration is required in Identify for this sample:

- client_id: Specify the client ID for the OIDC SPA application.
- redirect_uri: Must include /oidc_callback. For example:
If the SPA URL is https://spa-oidc.safewhere.local, the redirect_uri should be:
https://spa-oidc.safewhere.local/oidc_callback.
- client_secret: Specify the client secret for the OIDC SPA application.
- Enable the following options:
    - Allow code flow
    - Enable session status change notification
- CORS Configuration: CORS support must be enabled in the Identify system setup to allow cross-site requests. Add the SPA's address to the `Allowed domains in CORS origins header` setting. For example: https://spa-oidc.safewhere.local.

## Execution
Once the client setup is complete, access the application at: https://spa-oidc.safewhere.local or, for local development: https://localhost:5173
Verify that the application runs correctly.