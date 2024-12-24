import Oidc, { UserManager } from 'oidc-client';

const settings = {
    authority: import.meta.env.VITE_OAUTH_AUTHORITY,
    client_id: import.meta.env.VITE_OAUTH_CLIENT_ID,
    redirect_uri: `${window.location.origin}/oidc_callback`,
    post_logout_redirect_uri: `${window.location.origin}`,
    response_type: "code",
    scope: import.meta.env.VITE_OAUTH_SCOPE || "openid",
    monitorSession: true,
    automaticSilentRenew: true,
    userStore: new Oidc.WebStorageStateStore({
        store: window.sessionStorage,
    }),
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

    async login() {
        const nonce = this.generateNonce();
        await this.userManager.signinRedirect({
            extraQueryParams: {
                nonce: nonce
            },
        });
    }

    generateNonce() {
        return crypto.getRandomValues(new Uint8Array(16)).join('');
    }

    async handleCallback() {
        try {
            const user = await this.userManager.signinRedirectCallback();
            return user;
        }
        catch (e) {
            console.log("Error handling callback: ", e);
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

    async forceAuthn(securityLevel) {
        const nonce = this.generateNonce();
        await this.userManager.signinRedirect({
            extraQueryParams: {
                nonce: nonce,
                prompt: "login",
                acr_values: securityLevel
            },
        });
    }

    async reAuthenticate() {
        const nonce = this.generateNonce();
        const id_token = await this.getIdToken();
        await this.userManager.signinRedirect({
            extraQueryParams: {
                nonce: nonce,
                prompt: "none",
                id_token_hint: id_token,
            },
        });
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
            const header = JSON.parse(window.atob(token.split(".")[0]));
            const payload =  JSON.parse(window.atob(token.split(".")[1]));

            return { header, payload };
        } catch (e) {
            console.warn("Error decoding token");
        }
    }
}

export const authService = new AuthService();
