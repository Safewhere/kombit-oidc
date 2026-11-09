# US38464: FAPI 2.0 building blocks in the WebAppNetCore sample

Status: Implemented on 14 October 2026; waits for review and the live verification. [Section 12](#12-implementation-status) records the commits and the differences from the plan. Target: [`src/CSharp/WebAppNetCore`](../../../src/CSharp/WebAppNetCore) on .NET 10, with `Microsoft.AspNetCore.Authentication.OpenIdConnect` 10.0.12 and `Microsoft.IdentityModel` 8.19.2.

## 1. Context

Identify implements section 5 of the [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5) as independent building blocks. The Identify documents are in the Identify repository, in `docs/features/US38464/`:

- `fapi2-building-blocks-design.md`: the server behavior and the error contract.
- `fapi2-configuration-guide.md`: the connection settings for a FAPI client.
- `fapi2-analysis-handoff.md`, section 5.3.3: the sample client requirements.

The Identify plan says: "The sample client and the sample resource server get a separate, later plan." This document is the plan for the sample client. It updates WebAppNetCore so that a tester can demonstrate and test each Identify block, alone or combined.

The sample follows the Identify approach. It has no FAPI profile, and no code checks for "FAPI". Each client-side block has its own setting, or it is always available. A tester combines the blocks in `appsettings.json` to match an Identify connection. The README shows the FAPI 2.0 combination as an example.

## 2. Current state

These findings come from reading the code on `feature/38464-fapi` (commit `7b55df9`).

| Area | Current behavior | Effect |
|---|---|---|
| Authorization request | Direct GET or POST. `PushedAuthorizationBehavior.Disable` is hard-coded ([CustomOpenIdConnectAuthenticationExtension.cs:66](../../../src/CSharp/WebAppNetCore/WebAppNetCore/CustomOpenIdConnectAuthenticationExtension.cs#L66)). | No PAR. |
| Code redemption | Done by hand in `OnAuthorizationCodeReceived` with `new HttpClient()` ([:120-242](../../../src/CSharp/WebAppNetCore/WebAppNetCore/CustomOpenIdConnectAuthenticationExtension.cs#L120)). | A good place for DPoP. Tests cannot stub the call, and the call does not use `HttpClientHandlerProvider`. |
| Shared state | `accessToken`, `idToken`, and `sessionState` are locals of `InitializeConnectOptions`. Every event handler of every request captures the same variables ([:51-53](../../../src/CSharp/WebAppNetCore/WebAppNetCore/CustomOpenIdConnectAuthenticationExtension.cs#L51)). | Two concurrent sign-ins can mix their tokens. This must be fixed before more flow state is added. |
| Client assertion | `aud` is the token endpoint URL, `alg` is RS256, and the lifetime is 5 minutes, all hard-coded ([:160-176](../../../src/CSharp/WebAppNetCore/WebAppNetCore/CustomOpenIdConnectAuthenticationExtension.cs#L160)). | Fails the Identify rules `clientAssertion.audience=issuer` and `clientJwt.signingAlgorithms=PS256`. |
| Token response | `HandleCodeRedemption(accessToken, idToken)` drops `refresh_token`, `token_type`, and `expires_in` ([:238](../../../src/CSharp/WebAppNetCore/WebAppNetCore/CustomOpenIdConnectAuthenticationExtension.cs#L238)). | No refresh and no `token_type` check. |
| Errors | `EnsureSuccessStatusCode()` throws and loses the response body. `HomeController.Error` reads `HttpContext.Items["RemoteError"]`, but no code sets it. | A negative test does not show the OAuth `error`. |
| UserInfo | The handler calls UserInfo with the Bearer scheme (`GetClaimsFromUserInfoEndpoint = true`). | Identify rejects a DPoP-bound token with the Bearer scheme. Sign-in fails as soon as DPoP is on. |
| Endpoints | The token, UserInfo, and end-session URLs come from `IssuerDomain` and fixed paths ([ConfigurationExtensions.cs:44-62](../../../src/CSharp/WebAppNetCore/WebAppNetCore/ConfigurationExtensions.cs#L44)). The authorization endpoint comes from discovery. | FAPI 5.3.3.1 item 9 requires metadata. The DPoP `htu` must equal the public URL that Identify derives from its base URI. |
| Nonce | The handler nonce is about 115 characters: a timestamp and base64 of two GUIDs. | FAPI 5.3.3.2 item 7 allows at most 64 characters. |
| `iss` response parameter | ASP.NET Core 10.0.12 has no RFC 9207 check. This was verified in the package binary. | FAPI 5.3.3.2 item 5 is not met. |
| Session management | The home page and the RP iframe build a direct `prompt=none` authorization request ([OpenIdConnectHelper.cs:24-44](../../../src/CSharp/WebAppNetCore/WebAppNetCore/OpenIdConnectHelper.cs#L24)). | The request fails when the connection requires PAR. |
| Sign-in initiation | `GET /Account/SignIn` with query parameters and no antiforgery token. | FAPI 5.3.3.1 item 12 asks for CSRF protection of flow initiation. |
| Tests | Four integration tests. The backchannel rejects every call. No stub exists for the token endpoint. | The new flows need a stub Identify. |

Library facts that the design uses (verified in the restored packages):

- `OpenIdConnectEvents.OnPushAuthorization` gives a `PushedAuthorizationContext` with `HandlePush(requestUri)`, `SkipPush()`, and `HandleClientAuthentication()`. The handler's own push uses `client_secret_basic` by default and cannot add a `DPoP` header.
- `OpenIdConnectConfiguration` has `PushedAuthorizationRequestEndpoint`, `RequirePushedAuthorizationRequests`, `DPoPSigningAlgValuesSupported`, and `AuthorizationResponseIssParameterSupported`.
- `JsonWebKey` has `ComputeJwkThumbprint()` and `RepresentAsAsymmetricPublicJwkForDpop()`. `SecurityTokenDescriptor` has `TokenType`, `AdditionalHeaderClaims`, and `IncludeKeyIdInHeader`.
- `OpenIdConnectProtocolValidator.GenerateNonce()` is virtual, and `RequireTimeStampInNonce` can be turned off.
- `AuthorizationCodeReceivedContext.HandleCodeRedemption(OpenIdConnectMessage)` accepts the full token response.

Identify facts that the client must match (verified in the Identify source):

- PAR is at `{BaseUri}/oauth2/par.idp`, token at `{BaseUri}/oauth2/token.idp`, and UserInfo at `{BaseUri}/openidconnect/userinfo.idp`.
- The expected `htu` is `BaseUri` plus the endpoint path, normalized by RFC 3986, with the path case kept and the query ignored. The discovered endpoint URL is therefore the correct `htu`.
- With `clientAssertion.audience=issuer`, `aud` must be one JSON string that equals the issuer. The discovered `issuer` value is therefore the correct `aud`.
- Identify adds `offline_access` and issues a refresh token when the connection setting `AllowRefreshToken` is on. The sample does not need to request `offline_access`.

## 3. Decisions to confirm

| Topic | Proposal |
|---|---|
| Scope | WebAppNetCore only. The sample resource server stays a separate plan, as the Identify plan says. Identify UserInfo is the DPoP-protected resource in the demo, because Identify supports DPoP at UserInfo. |
| Methods | DPoP and `private_key_jwt`, as in the Identify configuration guide. No mTLS. |
| Configuration | New keys in the existing `OpenIdConnectOptions` section. No key named "FAPI". |
| PAR implementation | The handler decides when to push (`PushedAuthorizationBehavior`) and builds the browser redirect. The sample sends the PAR request itself in `OnPushAuthorization` and calls `HandlePush(requestUri)`. Reason: PAR must use the same client authentication as the token endpoint, and it must be able to carry a `DPoP` header. |
| DPoP key | A new RSA 2048 key for each sign-in, in an in-memory server-side store. The authentication properties carry only a random handle. After an application restart, UserInfo and refresh need a new sign-in. The alternative is one key for each application instance; it is simpler but cannot show a different `jkt` for each flow. |
| DPoP algorithm | PS256 by default. RS256 to PS512 can be configured, which is the Identify server set. No ES256 or EdDSA, because Identify does not support them. |
| UserInfo | The sample calls UserInfo itself in all cases, with the scheme that matches `token_type`. `GetClaimsFromUserInfoEndpoint` becomes false. The handler's claim actions and the `sub` check are kept. |
| Fault injection | Included, off by default (`Testing:EnableFaultInjection`). It makes the negative checks of the Identify configuration guide repeatable. |
| Sign-in initiation | `/Account/SignIn` becomes POST with an antiforgery token. |
| Session management | No code change. The README says to turn off `EnableSessionManagement` when the connection requires PAR. OIDC session management is not part of FAPI. |
| Delivery | Stage by stage, one commit for each work package, as for Identify. |

## 4. Design rules

1. Each block has its own setting, or it is always available. No setting turns on another setting.
2. The sample does not reject combinations of settings. It sends what the settings say, so that Identify's response to an impossible combination is visible. At startup, one log entry lists the active blocks and warns about the combinations in [section 5.4](#54-combinations-that-cannot-succeed) that the sample can detect.
3. Defaults keep the current behavior. [Section 6](#6-changes-to-current-behavior) lists the exceptions.
4. An invalid setting value fails at startup. It never reads as "off".
5. Diagnostics never show client secrets, private keys, or JWT signatures.

## 5. Configuration

### 5.1 New settings

All keys are in the `OpenIdConnectOptions` section, except the last one.

| Setting | Type, default | Standard | Behavior |
|---|---|---|---|
| `PushedAuthorization` | `Disable`, `UseIfAvailable`, `Require`; default `Disable` | RFC 9126 | Maps to `PushedAuthorizationBehavior`. When the request is pushed, the browser gets only `client_id` and `request_uri`, with GET or POST as `AuthorizationEndpointMethod` says. |
| `ClientAssertion:Audience` | `TokenEndpoint`, `Issuer`; default `TokenEndpoint` | RFC 7523; FAPI 5.3.3.1 item 5 | The `aud` of each client assertion, at the token and PAR endpoints. `Issuer` sends the discovered `issuer` as one JSON string. |
| `ClientAssertion:SigningAlgorithm` | RS256, RS384, RS512, PS256, PS384, PS512; default RS256 | FAPI 5.4.1 | The `alg` of the client assertion. |
| `DPoP:BindAccessTokens` | bool, false | RFC 9449 section 5 | Every token request (code and refresh) carries a DPoP proof. A token response with a `token_type` other than `DPoP` fails. |
| `DPoP:SendDPoPJkt` | bool, false | RFC 9449 section 10 | The authorization request, pushed or direct, carries `dpop_jkt`. |
| `DPoP:SendProofToParEndpoint` | bool, false | RFC 9449 section 10.1 | The PAR request carries a `DPoP` header. No effect on a direct request. |
| `DPoP:SigningAlgorithm` | RS256 to PS512; default PS256 | FAPI 5.4.1 | The `alg` of DPoP proofs. |
| `ValidIdTokenSigningAlgorithms` | comma list; empty keeps the library default | FAPI 5.4.1 | `TokenValidationParameters.ValidAlgorithms` for the ID token. |
| `Testing:EnableFaultInjection` | bool, false | None | Shows the fault controls of [WP9](#wp9-fault-injection). Top-level section. |

The existing settings `TokenAuthnMethod`, `JwtAssertionSigningCertPath`, `JwtAssertionSigningCertPassword`, `Scope`, `ResponseType`, and `AuthorizationEndpointMethod` keep their meaning. `TokenAuthnMethod` now applies at the PAR endpoint too, as it does in Identify.

### 5.2 Capabilities without a setting

- The token, PAR, and UserInfo endpoints come from discovery. The discovered `issuer` must equal `ClaimsIssuer` (FAPI 5.3.3.1 items 9 to 11).
- RFC 9207: a present `iss` must equal the discovered issuer. When discovery has `authorization_response_iss_parameter_supported=true`, a missing `iss` fails (FAPI 5.3.3.2 item 5).
- The nonce has 43 characters: 32 random bytes, base64url (FAPI 5.3.3.2 item 7).
- DPoP server nonce (FAPI 5.3.3.1 item 8): after `400` with `error=use_dpop_nonce` and a `DPoP-Nonce` header at the token or PAR endpoint, or `401` with `WWW-Authenticate: DPoP error="use_dpop_nonce"` at UserInfo, the sample retries once. The retry has a new proof with the nonce and a new client assertion. The sample keeps the latest `DPoP-Nonce` of each server, also from a successful response, for the next proofs to that server (RFC 9449 section 8.2): the PAR and token endpoints share the nonce of the authorization server, and UserInfo has its own. Identify does not send nonces, so only the unit tests cover this.
- UserInfo uses the scheme that matches the `token_type` of the stored token. A DPoP request has a proof with `ath`.
- Refresh uses the same DPoP key. The sample keeps the old refresh token when the response has none, and it stores a returned replacement (FAPI 5.3.3.1 item 6).
- The OAuth `error` and `error_description` from PAR, token, and UserInfo are shown on the error page or the home page.

### 5.3 Example: the FAPI 2.0 combination

```json
"OpenIdConnectOptions": {
  "TokenAuthnMethod": "private_key_jwt",
  "JwtAssertionSigningCertPath": "<from user secrets>",
  "JwtAssertionSigningCertPassword": "<from user secrets>",
  "ResponseType": "code",
  "Scope": "openid",
  "EnableSessionManagement": "false",
  "PushedAuthorization": "Require",
  "ClientAssertion": { "Audience": "Issuer", "SigningAlgorithm": "PS256" },
  "DPoP": { "BindAccessTokens": true, "SendDPoPJkt": true, "SendProofToParEndpoint": false, "SigningAlgorithm": "PS256" },
  "ValidIdTokenSigningAlgorithms": "PS256"
}
```

The matching Identify connection is described in steps 1 to 4 of the Identify configuration guide. The redirect URI must use HTTPS, because that guide sets `AllowHttpRedirect=false` and `authorize.redirectUriScheme=https`.

### 5.4 Combinations that cannot succeed

These combinations are useful negative checks. The startup log warns about the first one, because the sample can detect it alone.

| Sample settings | Identify connection | Result |
|---|---|---|
| `SendDPoPJkt=true`, `BindAccessTokens=false` | Any | The code is bound to the key. The redemption has no proof, so it fails. |
| `PushedAuthorization=Disable` | `RequirePushedAuthorizationRequests=true` | `invalid_request` at the authorization endpoint. |
| `ClientAssertion:Audience=TokenEndpoint` | `clientAssertion.audience=issuer` | `invalid_client` at PAR (401) and at the token endpoint. |
| `ClientAssertion:SigningAlgorithm` not in the rule | `clientJwt.signingAlgorithms` | `invalid_client`. |
| `DPoP:SigningAlgorithm` not in the rule | `clientJwt.signingAlgorithms` | `invalid_dpop_proof`. |
| `BindAccessTokens=false` | `RequireDPoPBoundAccessTokens=true` | `invalid_dpop_proof`. |
| `EnableSessionManagement=true`, `PushedAuthorization` any | `RequirePushedAuthorizationRequests=true` | The session check iframe gets the Identify error page. |

## 6. Changes to current behavior

1. `/Account/SignIn` accepts only POST with an antiforgery token. The buttons on the page become forms.
2. The nonce has 43 characters.
3. The token and UserInfo endpoints come from discovery.
4. Sign-in fails when the discovered issuer differs from `ClaimsIssuer`, when `iss` is wrong, or when `iss` is missing while discovery advertises it.
5. The sample calls UserInfo, not the handler. The claims are the same, because the sample runs the handler's claim actions.
6. A failed token request shows `error` and `error_description` on the error page instead of an unhandled exception.
7. The token request uses a named `HttpClient` with `HttpClientHandlerProvider`. The DEBUG certificate bypass therefore applies to the token request too.

## 7. Design

### 7.1 Components

New files, in a new folder `OAuth/` (not "Fapi", because no code is FAPI-specific):

| File | Responsibility |
|---|---|
| `OAuth/IdentifyMetadata.cs` | Reads discovery through `OpenIdConnectOptions.ConfigurationManager`. Checks that `issuer` equals `ClaimsIssuer`. Gives the token, PAR, and UserInfo endpoints and the RFC 9207 flag. |
| `OAuth/ClientAuthentication.cs` | Adds `client_secret_post`, `client_secret_basic`, or `private_key_jwt` to a request for any endpoint. The assertion has `iss` and `sub` equal to the client ID, `aud` from `ClientAssertion:Audience`, a new `jti`, `iat`, `exp`, the `kid` of today, and `alg` from `ClientAssertion:SigningAlgorithm`. |
| `OAuth/DPoPKey.cs` | An RSA 2048 key, its public JWK (`kty`, `n`, `e` only), and its RFC 7638 thumbprint. |
| `OAuth/DPoPProofFactory.cs` | Creates a proof. Header: `typ=dpop+jwt`, `alg`, `jwk`, no `kid`. Claims: `jti`, `htm`, `htu` without query and fragment, `iat`, `ath` for resource requests, and `nonce` when the server has sent one. No `exp` or `nbf` (`SetDefaultTimesOnTokenCreation=false`). |
| `OAuth/ClientSessionStore.cs` | An in-memory store (`IMemoryCache`, sliding expiration) of the state of each sign-in, by a random handle: the DPoP key and the protocol trace. |
| `OAuth/PushedAuthorizationClient.cs` | Sends the PAR request: the parameters of the handler's message, the client authentication, and an optional `DPoP` header. Retries once on `use_dpop_nonce`. Returns `request_uri` and `expires_in`. Any status other than 201 fails with the OAuth error. |
| `OAuth/TokenClient.cs` | The `authorization_code` and `refresh_token` grants, with client authentication, an optional proof, the nonce retry, and the `token_type` check. Returns an `OpenIdConnectMessage`. |
| `OAuth/UserInfoClient.cs` | Calls UserInfo with the Bearer scheme, or with the DPoP scheme and a proof with `ath`. Retries once on `use_dpop_nonce`. Checks that `sub` equals the ID token `sub`. |
| `OAuth/ShortNonceProtocolValidator.cs` | Overrides `GenerateNonce()`. Sets `RequireTimeStampInNonce=false`. |
| `OAuth/ProtocolTrace.cs` | A redacted record of the PAR request and response, the authorization response, the token request and response, UserInfo, and refresh. |
| `OAuth/FaultInjection.cs` | The faults of [WP9](#wp9-fault-injection). |

Changed files: `CustomOpenIdConnectAuthenticationExtension.cs`, `ConfigurationExtensions.cs`, `Startup.cs`, `Controllers/AccountController.cs`, `Controllers/HomeController.cs`, `Views/Home/Index.cshtml`, `Views/Shared/_LoginPartial.cshtml`, `appsettings.json`, `README.md`, and the test project.

The new settings follow the idiom of `ConfigurationExtensions.cs`: one extension method for each setting. Enum and algorithm values are parsed strictly, and `Startup` reads all of them once, so an invalid value fails at startup (rule 4).

### 7.2 Flow through the handler events

1. `OnRedirectToIdentityProvider`: create the handle in `Properties.Items`. If any DPoP setting is on, create the key. If `SendDPoPJkt` is on, add `dpop_jkt`. Add `acr_values` and `max_age` as today. Items set here go into the protected `state`.
2. The handler protects `state`. If it pushes, it raises `OnPushAuthorization`. The sample calls `HandleClientAuthentication()`, sends the request through `PushedAuthorizationClient`, and calls `HandlePush(requestUri)`. The handler redirects the browser with `client_id` and `request_uri`.
3. `OnMessageReceived`: the RFC 9207 check. A failure calls `context.Fail`.
4. `OnAuthorizationCodeReceived`: `TokenClient` redeems the code. The ID token decryption stays as today. `HandleCodeRedemption(tokenResponse)` gets the full response, so `SaveTokens` stores `refresh_token`, `token_type`, and `expires_at`.
5. `OnTokenValidated`: the `session_state` claim from `context.TokenEndpointResponse`, the UserInfo call, the claim actions, and the `sid` record for back-channel logout.
6. `OnRemoteFailure`: shows the OAuth error on the error page.
7. After sign-in, the cookie ticket holds the tokens and the handle. `/Account/UserInfo` and `/Account/Refresh` read them.

The order in steps 1 and 2 comes from the handler source. WP5 has a test that shows it.

## 8. Work packages

### Stage A: foundations, no new protocol behavior

#### WP1: Stub Identify for tests

- `TestWebApplicationFactory` gets a programmable stub for discovery (with a test signing key), PAR, token, and UserInfo, through the named `HttpClient`.
- A helper drives `SignIn`, reads the correlation and nonce cookies and the `state`, and calls `/signin-oidc` with a code and an ID token that the test key signs.
- A new end-to-end test covers the current `client_secret_post` flow.
- Verification: the new test and the four existing tests pass.

#### WP2: Refactor code redemption

- Remove the shared `accessToken`, `idToken`, and `sessionState` variables.
- Add the named `HttpClient` "Identify" with `HttpClientHandlerProvider.Create()`.
- Move client authentication to `ClientAuthentication`, with today's behavior (token endpoint `aud`, RS256).
- Pass the full token response to `HandleCodeRedemption`.
- Add `IdentifyMetadata`, and take the token endpoint from discovery.
- Add `OnRemoteFailure`, and show the OAuth error on the error page.
- Verification: end-to-end tests for `client_secret_post`, `client_secret_basic`, and `private_key_jwt`, and a test for a token error.

#### WP3: Client hygiene

- `/Account/SignIn` becomes POST with an antiforgery token. `_LoginPartial.cshtml` uses forms.
- `ShortNonceProtocolValidator`.
- `ValidIdTokenSigningAlgorithms`.
- `UserInfoClient` with the Bearer scheme, `GetClaimsFromUserInfoEndpoint=false`, the claim actions, and the `sub` check.
- Verification: the nonce in the authorization request has at most 64 characters; a GET to `/Account/SignIn` fails; an ID token with an algorithm that is not allowed fails; the UserInfo claims reach the principal. The existing sign-in tests change to POST.

Stage A ends with a review.

### Stage B: building blocks

#### WP4: Client assertion

- `ClientAssertion:Audience` and `ClientAssertion:SigningAlgorithm`.
- Verification: with `Issuer`, `aud` is one JSON string equal to the discovered issuer, not an array; the header has `alg=PS256` when configured; the `kid` is unchanged.

#### WP5: Pushed authorization requests

- `PushedAuthorization`, `OnPushAuthorization` with `HandlePush`, and `PushedAuthorizationClient`.
- The PAR request uses the configured client authentication, also `client_secret_basic`.
- Verification: the browser redirect has exactly `client_id` and `request_uri`, with GET and with POST; the PAR body has `response_type=code`, `redirect_uri`, `scope`, `state`, `nonce`, `code_challenge`, `code_challenge_method=S256`, `acr_values`, `max_age`, and `prompt`; the `state` in the PAR body contains the handle (this shows the order in [section 7.2](#72-flow-through-the-handler-events)); a PAR error shows the OAuth error; with `Disable` nothing is pushed, as today.

#### WP6: Authorization response issuer

- The RFC 9207 check in `OnMessageReceived`.
- Verification: four cases. Matching `iss`: success. Wrong `iss`: failure. Missing `iss` with the flag in discovery: failure. Missing `iss` without the flag: success.

#### WP7: DPoP

- `DPoPKey`, `ClientSessionStore`, and `DPoPProofFactory`.
- The proof at the token endpoint, `dpop_jkt`, the proof at PAR, the `token_type` check, UserInfo with the DPoP scheme, and the nonce retry.
- Verification:
  - The thumbprint of the RFC 7638 section 3.1 example key is `NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`.
  - The proof header has `typ`, `alg`, and a `jwk` without `d`, `p`, `q`, `dp`, `dq`, or `qi`, and has no `kid`.
  - `htu` equals the discovered endpoint. `ath` is the base64url SHA-256 of the access token. Each proof has a new `jti`.
  - The nonce retry happens once, with the nonce claim and a new assertion `jti`.
  - A `Bearer` token response fails when `BindAccessTokens` is on.
  - An end-to-end test with all DPoP settings on.

Stage B ends with a review.

### Stage C: demonstration and test aids

#### WP8: Refresh and the home page

- `POST /Account/Refresh` and `POST /Account/UserInfo`, both with antiforgery tokens.
- Home page panels:
  - The active building blocks.
  - The token binding: `token_type`, the access token `cnf.jkt`, the local thumbprint, and whether they match.
  - PAR: `request_uri` and `expires_in`.
  - The RFC 9207 result.
  - The last DPoP proof and client assertion, decoded, without signatures.
  - The protocol trace and the last UserInfo response.
- Verification: refresh keeps the DPoP key; refresh keeps the old refresh token when the response has none; refresh stores a returned replacement; the home page renders for an anonymous user and for a user without DPoP.

#### WP9: Fault injection

When `Testing:EnableFaultInjection` is true, the page shows a fault list next to the Sign in, UserInfo, and Refresh buttons. A sign-in fault goes into `Properties.Items`, so that the later steps of the same flow can read it. When the setting is false, the server ignores the fault field and the page does not show it.

The expected results come from section 5 of the Identify design. Results marked "verify" are not in that table and must be confirmed in the live test.

| Fault | Step | Change | Expected Identify result |
|---|---|---|---|
| `SkipPar` | Authorization | A direct request, also when PAR is on | `invalid_request` when the connection requires PAR |
| `ExtraBrowserParameter` | Authorization | `scope` next to `request_uri` in the browser request; GET with PAR only, otherwise the sign-in does not start | Error response (verify) |
| `AssertionAudienceArray` | PAR, token | `aud` as a JSON array that contains the issuer | `invalid_client` with `clientAssertion.audience=issuer` |
| `AssertionFutureIat` | PAR, token | `iat` 120 seconds in the future | `invalid_client` when `clientJwt.clockSkewInSeconds` is below 120 |
| `ParProofKeyMismatch` | PAR | The PAR proof uses another key than `dpop_jkt` | `invalid_request` |
| `NoDPoPProof` | Token | No proof | `invalid_dpop_proof` when DPoP is required; an error for a bound code (verify) |
| `WrongDPoPKey` | Token | The proof uses a new key | `invalid_grant` for a bound code |
| `WrongHtu` | Token | `htu` is the authorization endpoint | `invalid_dpop_proof` |
| `SmallDPoPKey` | Token | An RSA 1024 key | `invalid_dpop_proof` |
| `RedeemCodeTwice` | Token | A second redemption after a successful one | `invalid_grant` |
| `BearerAtUserInfo` | UserInfo | The Bearer scheme with a DPoP-bound token | `invalid_token` |
| `MissingAth` | UserInfo | A proof without `ath` | `invalid_token` |
| `ReplayDPoPProof` | UserInfo | The same proof in two calls | The second call gets `invalid_token` |
| `NewDPoPKeyOnRefresh` | Refresh | A new key for the refresh request | Success; the new access token has a new `cnf.jkt` (confidential client, design section 4.4) |

Verification: for each fault, a test shows that the outgoing request changes as the table says, against the stub.

#### WP10: Documentation

- README: a section on the building blocks, with the settings table, the mapping in [section 9](#9-fapi-20-client-requirements-and-settings), the example in section 5.3, and the combinations in section 5.4.
- README: the Identify setup. A pointer to the Identify configuration guide; the client JWKS (the public key of the assertion certificate, `use=sig`, `kid` as the sample computes it, and no `alg` or an `alg` that matches `ClientAssertion:SigningAlgorithm`); an HTTPS redirect URI; and certificate passwords in user secrets, not in `appsettings.json`.
- README: the live checklist. It follows "Check the configuration" in the Identify configuration guide and uses the faults of WP9.
- `appsettings.json`: the new keys with their defaults and short comments, as the existing keys have.

Stage C ends with a review.

### Live verification

After Stage C, run the sample against an Identify Runtime built from `feature/38464-fapi`, with a connection configured as the Identify configuration guide describes. Run the live checklist, and record the results and the "verify" rows of WP9. This run also gives the deployed-Runtime smoke test that the Identify progress document lists as an open item: PAR, the authorization request with `request_uri`, login, and token issuance. Live tests need the approved rules of engagement that the Identify configuration guide names.

## 9. FAPI 2.0 client requirements and settings

| FAPI item | Setting or capability |
|---|---|
| 5.3.3.1-1 sender binding | `DPoP:BindAccessTokens=true`; the faults `WrongDPoPKey` and `BearerAtUserInfo` show the rejection |
| 5.3.3.1-2 client authentication | `TokenAuthnMethod=private_key_jwt`; the certificate password in user secrets |
| 5.3.3.1-3 token transport | UserInfo with `Authorization: DPoP` |
| 5.3.3.1-4 redirect safety | The application redirects only to local paths |
| 5.3.3.1-5 assertion audience | `ClientAssertion:Audience=Issuer` |
| 5.3.3.1-6 refresh | `/Account/Refresh`; replacement storage |
| 5.3.3.1-7 mTLS aliases | Not applicable; the sample uses DPoP |
| 5.3.3.1-8 DPoP nonce | Always supported; unit tests only, because Identify sends no nonce |
| 5.3.3.1-9 metadata | Endpoints from discovery |
| 5.3.3.1-10 trusted issuer | `ClaimsIssuer` in the application configuration |
| 5.3.3.1-11 issuer consistency | The discovered issuer must equal `ClaimsIssuer` |
| 5.3.3.1-12 initiation protection | POST sign-in with an antiforgery token; the handler's correlation cookie binds the flow to the browser |
| 5.3.3.1-13 least privileges | `Scope=openid` |
| 5.3.3.2-1 code grant | `ResponseType=code` |
| 5.3.3.2-2 PAR | `PushedAuthorization=Require` |
| 5.3.3.2-3 S256 | Always; the handler uses S256 |
| 5.3.3.2-4 fresh bound challenge | Always; the handler creates a verifier for each flow and protects it in `state` |
| 5.3.3.2-5 response issuer | Always; the RFC 9207 check |
| 5.3.3.2-6 browser parameters | `PushedAuthorization=Require`; the handler sends only `client_id` and `request_uri` |
| 5.3.3.2-7 nonce length | Always; 43 characters |
| 5.4.1 algorithms | `ClientAssertion:SigningAlgorithm=PS256`, `DPoP:SigningAlgorithm=PS256`, `ValidIdTokenSigningAlgorithms=PS256`; RSA 2048 keys |

## 10. Risks and open items

- The handler's PAR internals (the order in section 7.2 and the redirect after `HandlePush`) are not public contract. WP5 tests them, so a package update that changes them breaks a test.
- The in-memory store works for one instance only. A restart or a second instance loses the DPoP keys, and UserInfo and refresh then show an error that asks for a new sign-in.
- The results marked "verify" in WP9 depend on Identify behavior that its design does not state.
- The handler's `state` is long. It goes into the PAR request and back in the redirect, as it does today. No change is expected, but the live test confirms that Identify accepts it in PAR.
- Identify does not support the DPoP server nonce, ES256, EdDSA, or request objects inside PAR. The sample therefore does not use them, except the nonce retry, which unit tests cover.

## 11. Out of scope

- The sample resource server. Identify UserInfo is the DPoP-protected resource in the demo. The contract of the sample resource server is in [sample-resource-server-contract.md](sample-resource-server-contract.md) (US38477).
- mTLS client authentication and certificate-bound tokens.
- Request objects (JAR) inside PAR.
- OIDC session management together with required PAR.
- Token revocation at sign-out.
- The Java, JavaScript, and WPF samples.

## 12. Implementation status

Last update: 14 October 2026. Branch `feature/38464-fapi`. The decisions in section 3 were implemented as proposed. All work packages are committed. Nothing is pushed. The test project has 85 tests, and all pass.

| WP | Commit | Tests added |
|---|---|---|
| Plan | `8912fc0` | None |
| WP1 Stub Identify | `b507b93` | The current code flow end to end |
| WP2 Refactor code redemption | `c69f9ee` | The three client authentication methods, the token endpoint from discovery, the error page, the issuer check, and the ID token nonce |
| WP3 Client hygiene | `24b53c1` | POST sign-in, the 43-character nonce, ID token algorithms, UserInfo claims, signed UserInfo, and the UserInfo `sub` check |
| WP4 Client assertion | `54cfc1d` | `aud` as one JSON string, PS256, and invalid values |
| WP5 PAR | `f66d34f` | The pushed parameters, the browser parameters for GET and POST, the state order, client authentication, errors, and `UseIfAvailable` |
| Thread-safety fix | `2fa1697` | 20 concurrent sign-ins |
| WP6 RFC 9207 | `1ebbf13` | The four `iss` cases and an error response |
| WP7 DPoP | `e11f416` | The RFC 7638 vector, the proof contents, the key of each step, the nonce retries, and the `token_type` check |
| WP8 Refresh and home page | `ddf7e7d` | Refresh, UserInfo, the protocol panels, redaction, warnings, and a lost session state |
| WP9 Fault injection | `b6d982e` | Each fault against the stub |
| WP10 Documentation | This commit | None |

Differences from the plan and facts found during the implementation:

- The handler skips `ValidateTokenResponse` when the application redeems the code (`HandledCodeRedemption`). The sample therefore did not check the ID token nonce before, although `RequireNonce` was true. `OnTokenValidated` now calls `ValidateTokenResponse`. A test shows that an ID token with another nonce failed before the change and fails now.
- `OpenIdConnectHelper.LiveSessions` was a static `Dictionary` that every sign-in writes. Concurrent sign-ins corrupted it ("Operations that change non-concurrent collections must have exclusive access"). It is a `ConcurrentDictionary` now, in a separate commit. The concurrency test fails in most runs with the old type.
- `OpenIdConnectMessage.CreateAuthenticationRequestUrl()` adds the telemetry parameters `x-client-SKU` and `x-client-ver`. After a push, the browser request would carry them next to `request_uri`. `DisableTelemetry` is true now, also for direct requests.
- The PAR event allows only one of `HandlePush`, `SkipPush`, and `HandleClientAuthentication`. The sample calls only `HandlePush`; the handler then sends nothing itself.
- The plan put the result of a UserInfo or refresh action in the protocol panel. It is at the top of the home page instead, because the token display above the panel is long.
- The stub Identify uses the Runtime path layout (`/runtime/oauth2/...`), so that WP1 could test the earlier code, which built the token URL from `IssuerDomain`.
- `/test/session` exists only in the test host. It returns the claims, tokens, and items of the cookie session.
- The live checklist is not in the README. The live test documentation is kept outside this repository.

Open items:

- The review of each stage by the user.
- The live verification in section 8, including the WP9 rows marked "verify".
