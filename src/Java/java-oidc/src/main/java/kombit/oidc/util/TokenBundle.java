package kombit.oidc.util;

public class TokenBundle {
    private String accessToken;
    private String refreshToken;
    private String idToken;

    public TokenBundle(String accessToken, String refreshToken, String idToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.idToken = idToken;
    }
    public String getAccessToken() { return accessToken; }
    public String getRefreshToken() { return refreshToken; }
    public String getIdToken() { return idToken; }
}
