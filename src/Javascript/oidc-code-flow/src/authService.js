import Oidc, { UserManager, SessionMonitor } from 'oidc-client';

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
        const extraQueryParams = {
            nonce: nonce,
        }

        if (isForceAuthn) {
            extraQueryParams.prompt = "login";
        } else if (isPassive) {
            extraQueryParams.prompt = "none";
        }
        
        if (securityLevel) {
            extraQueryParams.acr_values = securityLevel;
        }

        if (maxAge) {
            extraQueryParams.max_age = maxAge;
        }

        if (isPost) {
            await this.userManager.signinPost({
                extraQueryParams: {
                    ...extraQueryParams
                },
            });
        }
        else {
            await this.userManager.signinRedirect({
                extraQueryParams: {
                    ...extraQueryParams
                },
            });
        }
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
            console.log("Error handling callback: ", e);
            throw e;
        }
    }

    async logout() {
        const user = await this.getUser();
        const id_token =  user ? user.id_token : null;
        try {
            await this.userManager.signoutRedirect({ id_token_hint: id_token });
        }
        catch (e) {
            console.error("Error logging out", e);
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
}

export const authService = new AuthService();
