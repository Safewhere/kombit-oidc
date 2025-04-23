import Oidc, { UserManager, SessionMonitor } from 'oidc-client';
import { sessionStore } from './storageHelper';
import { isAuthReady } from './useAuthState'
import { AUTH_FORM_SETTINGS, CODE_VERIFIER_KEY } from './constants'; 

const settings = {
    authority: import.meta.env.VITE_OAUTH_AUTHORITY,
    client_id: import.meta.env.VITE_OAUTH_CLIENT_ID,
    redirect_uri: `${window.location.origin}/oidc_callback`,
    post_logout_redirect_uri: `${window.location.origin}`,
    response_type: "code",
    scope: import.meta.env.VITE_OAUTH_SCOPE || "openid",
    monitorSession: false, // Disable session monitoring, the built-in session monitor is not used because it does note support forceAuthn correctly. We manually construct it in handleCallback to have a new session-state for each login.
    automaticSilentRenew: true,
    stateStore: new Oidc.WebStorageStateStore({
        store: window.sessionStorage,
    }),
    extraQueryParams: {
        nonce: "default-nonce",
    },
};

class CustomUserManager extends UserManager {
    _signinStart(args, navigator, navigatorParams = {}) {
        return navigator.prepare(navigatorParams).then(handle => {
            return this.createSigninRequest(args).then(signinRequest => {
                let url = new URL(signinRequest.url);
                url.searchParams.delete("response_mode");
                
                navigatorParams.url = url.toString();
                navigatorParams.id = signinRequest.state.id;
                
                sessionStore.set(CODE_VERIFIER_KEY, signinRequest.state.code_verifier);
                
                return handle.navigate(navigatorParams);
            }).catch(err => {
                if (handle.close) {
                    handle.close();
                }
                throw err;
            });
        });
    }

    signinRedirect(args = {}) {
        args = Object.assign({}, args);

        args.request_type = "si:r";
        let navParams = {
            useReplaceToNavigate : args.useReplaceToNavigate
        };
        return this._signinStart(args, this._redirectNavigator, navParams).then(()=>{
            console.log("UserManager.signinRedirect: successful");
        });
    }

    signinPost(args = {}) {
        args = Object.assign({}, args);

        args.request_type = "si:p";
        let navParams = {
            useReplaceToNavigate: args.useReplaceToNavigate
        };

        return this._signinStartPost(args, this._redirectNavigator, navParams).then(() => {
            console.log("UserManager.signinPost: successful");
        });
    }

    _signinStartPost(args, navigator, navigatorParams = {}) {
        return navigator.prepare(navigatorParams).then(handle => {
            return this.createSigninRequest(args).then(signinRequest => {
                let url = new URL(signinRequest.url);
                url.searchParams.delete("response_mode");

                const form = document.createElement("form");
                form.method = "POST";
                form.action = url.origin + url.pathname;

                url.searchParams.forEach((value, key) => {
                    const input = document.createElement("input");
                    input.type = "hidden";
                    input.name = key;
                    input.value = value;
                    form.appendChild(input);
                });

                document.body.appendChild(form);
                form.submit();

                return Promise.resolve(); // Since navigation happens via form submission
            }).catch(err => {
                if (handle.close) {
                    handle.close();
                }
                throw err;
            });
        });
    }

    async signinSilent(args = {}) {
        console.log("[signinSilent] called");
        args = Object.assign({}, args);
        try {
            const user = await this._loadUser();
            if (user && user.refresh_token) {
                try {
                    return await this._useRefreshToken({ ...args, refresh_token: user.refresh_token });
                } catch (err) {
                    console.error("[signinSilent] Refresh token failed");

                    const { isAuthnMethodPost } = sessionStore.get(AUTH_FORM_SETTINGS) || {};
                    const extraQueryParams = {
                        nonce: this._settings.extraQueryParams.nonce,
                        prompt: "login"
                    };

                    this.prepareSigninParams(extraQueryParams);

                    console.log("[signinSilent] Attempting to sign in via redirect or POST: ", extraQueryParams);

                    return isAuthnMethodPost
                        ? this.signinPost({ extraQueryParams })
                        : this.signinRedirect({ extraQueryParams });
                    
                } finally {
                    isAuthReady.value = true;
                }
                
            }

            // If no refresh token, proceed with silent sign-in use iframe
            args.request_type = "si:s";
            if (user && this._settings.validateSubOnSilentRenew) {
                console.log("[signinSilent] subject prior to silent renew: ", user.profile.sub);
                args.current_sub = user.profile.sub;
            }

            try {
                return this._signinSilentIframe(args);
            } catch (err) {
                console.error("[signinSilent] Silent sign-in iframe failed: ", err);
            } finally {
                isAuthReady.value = true;
            }

        } catch (err) {
            console.error("[signinSilent] Error: ", err);
            isAuthReady.value = true;
            throw err;
        }
    }

    async _useRefreshToken(args = {}) {
        const result = await this.exchangeRefreshToken(args);

        if (!result) {
            throw new Error("No response returned from token endpoint");
        }

        if (!result.access_token) {
            throw new Error("No access token returned from token endpoint");
        }

        const user = await this._loadUser();
        if (!user) return null;

        if (result.id_token) {
            await this._validateIdTokenFromTokenRefreshToken(user.profile, result.id_token);
        }
    
        user.id_token = result.id_token || user.id_token;
        user.access_token = result.access_token;
        user.refresh_token = result.refresh_token || user.refresh_token;
        user.expires_in = result.expires_in;

        await this.storeUser(user);
        this._events.load(user);
        return user;
    }

    async exchangeRefreshToken(args = {}) {
        args = Object.assign({}, args);
        
        args.grant_type = args.grant_type || "refresh_token";
        args.client_id = args.client_id || this._settings.client_id;
        args.redirect_uri = settings.redirect_uri;
        args.code_verifier = sessionStore.get(CODE_VERIFIER_KEY);

        const client_authentication = args._client_authentication || this._settings._client_authentication;
        delete args._client_authentication;
    
        if (!args.refresh_token) {
            console.error("[exchangeRefreshToken]]: No refresh_token passed");
            throw new Error("A refresh_token is required");
        }
    
        if (!args.client_id && client_authentication !== "client_secret_basic") {
            console.error("[exchangeRefreshToken]]: No client_id passed");
            throw new Error("A client_id is required");
        }
    
        const headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        };
    
        const bodyParams = { ...args };
    
        if (client_authentication === "client_secret_basic") {
            const basicAuth = btoa(`${args.client_id}:${args.client_secret}`);
            headers["Authorization"] = `Basic ${basicAuth}`;
            delete bodyParams.client_id;
            delete bodyParams.client_secret;
        }
    
        try {
            const tokenEndpoint = await this._metadataService.getTokenEndpoint(false);
            const body = new URLSearchParams(bodyParams).toString();
            const response = await fetch(tokenEndpoint, { method: "POST", headers, body });
            if (!response.ok) {
                const errorBody = await response.text();
                console.error("[exchangeRefreshToken]: Failed", response.status, errorBody);
                throw new Error(`Token endpoint returned ${response.status}: ${errorBody}`);
            }

            return response.json();
        } catch (err) {   
            console.error("[exchangeRefreshToken]: Failed to get token endpoint", err);
            throw err;
        }
    }

    prepareSigninParams(queryParams) {
        const { selectedSecurityLevel, maxAge } = sessionStore.get(AUTH_FORM_SETTINGS) || {};

        if (selectedSecurityLevel) 
            queryParams.acr_values = selectedSecurityLevel;

        if (maxAge !== null && maxAge >= 0) 
            queryParams.max_age = maxAge;
    }
}

class AuthService {
    constructor() {
        this.userManager = new CustomUserManager(settings);
        this.setupEventListeners();
    }

    setupEventListeners() {
        this.userManager.events.addUserSignedOut(async () => {
            console.log("User signed out event triggered.");
            await this.logout();
        });
    }

    async login(securityLevel, maxAge, isForceAuthn, isPassive, isPost) {
        const nonce = this.generateNonce();
        const extraQueryParams = { nonce }

        if (isForceAuthn) {
            extraQueryParams.prompt = "login";
        } else if (isPassive) {
            extraQueryParams.prompt = "none";
        }
        
        if (securityLevel) {
            extraQueryParams.acr_values = securityLevel;
        }

        if (maxAge !== null && maxAge >= 0) {
            extraQueryParams.max_age = maxAge;
        }

        this.persistAuthSettings(securityLevel, maxAge, isPost);

        return isPost
            ? this.userManager.signinPost({ extraQueryParams })
            : this.userManager.signinRedirect({ extraQueryParams });
    }

    generateNonce() {
        return crypto.getRandomValues(new Uint8Array(16)).join('');
    }

    async handleCallback() {
        try {
            const user = await this.userManager.signinRedirectCallback();
            // rebuild the session monitor with the new session state to avoid automatic logout.
            console.log("User signed in successfully: ", user.profile.sub + '|' + user.session_state);
            this.userManager._sessionMonitor = new SessionMonitor(this.userManager);
            return user;
        }
        catch (e) {
            console.error("[handleCallback] Error handling callback: ", e);
            throw e;
        }
    }

    async logout() {
        const user = await this.getUser();
        const id_token =  user ? user.id_token : null;
        try {
            await this.userManager.signoutRedirect({ id_token_hint: id_token });
            sessionStore.clear();
        }
        catch (e) {
            console.error("[logout] Error logging out", e);
        }
    }

    async getUser() {
        const user = await this.userManager.getUser();
        return user;
    }

    async isAuthenticated() {
        const user = await this.getUser();
        return user && !user.expired;
    }

    async getAccessToken() {
        const user = await this.getUser();
        return user ? user.access_token : null;
    }

    async getIdToken() {
        const user = await this.getUser();
        return user ? user.id_token : null;
    }

    async decodeToken(token) {
        try {
            const [headerB64, payloadB64] = token.split(".");
    
            const decodeBase64 = (b64) => {
                const binary = atob(b64);
                // Decode UTF-8 safely
                const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
                return new TextDecoder("utf-8").decode(bytes);
            };
    
            const header = JSON.parse(decodeBase64(headerB64));
            const payload = JSON.parse(decodeBase64(payloadB64));
    
            return { header, payload };
        } catch (e) {
            console.warn("Error decoding token:", e);
            return null;
        }
    }

    persistAuthSettings(securityLevel, maxAge, isPost) {
        sessionStore.set(AUTH_FORM_SETTINGS, {
            selectedSecurityLevel: securityLevel,
            maxAge: maxAge,
            isAuthnMethodPost: isPost,
        });
    }
}

export const authService = new AuthService();
