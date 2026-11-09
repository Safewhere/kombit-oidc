# US38477: contract of the FAPI 2.0 sample resource server

Status: Implemented, 9 November 2026 (US38477, AC-38477-05). The contract was agreed before the code was added. The projects `SampleApi` and `SampleApi.Tests` implement it, and the client sample calls it (section 10). The DPoP demonstration at Identify UserInfo does not replace it.

## 1. Purpose

The sample resource server is a small API that shows how a protected resource accepts a FAPI 2.0 access token from Identify. It covers the resource server requirements of [FAPI 2.0 Security Profile section 5.3.4](https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.4). Identify UserInfo is an Identify endpoint, so it cannot show what a customer API must check. The API is a sample: it has no persistence, and it runs as one instance.

## 2. Place and framework

| Item | Value |
|---|---|
| Repository | kombit-oidc |
| Project | `src/CSharp/WebAppNetCore/SampleApi`, in `WebAppNetCore.sln`, so that the client and the API build together |
| Tests | `src/CSharp/WebAppNetCore/SampleApi.Tests` (xUnit), with a stub Identify for discovery, JWKS, and introspection |
| Framework | ASP.NET Core, net10.0, the same version as WebAppNetCore |
| Libraries | `Microsoft.IdentityModel.JsonWebTokens` and `Microsoft.IdentityModel.Protocols.OpenIdConnect` for the token, the JWKS, and discovery. The DPoP proof check is code of the sample, so that a reader can see each step. |
| Address | `https://localhost:44392` |

## 3. Identify setup

Two connections take part. Both use `private_key_jwt`.

| Connection | Role | Settings that the API needs |
|---|---|---|
| The client connection, for example `FAPI-TEST confidential` | Gets the access token | `ApplicationAudience` contains the API identifier (section 4). The connection knows the scopes of section 4. It must not get the audience `EntityIdentifier`, because the Admin REST API and the Runtime `/api/` routes accept that audience (SWSEC-2026-0055). |
| A connection for the API, for example `FAPI-TEST sample API` with the client ID `fapi-test-api` | Calls introspection | `AllowTokenRevocationAndIntrospection` is true. It needs no grant type. It authenticates with a client assertion with the issuer as `aud`. Identify lets any client of the same authorization server introspect a token. |

Identify puts every value of `ApplicationAudience` of the client connection into `aud` of the access token. A request parameter cannot select the audience.

## 4. Audience and scopes

| Item | Value |
|---|---|
| API identifier (`aud`) | `urn:kombit-oidc:sample-api` |
| Read scope | `sample-api.read` |
| Write scope | `sample-api.write` |

The API checks the scope of the access token, not the scope of the authorization request. After a remembered consent, Identify can issue a scope that the client did not request in this sign-in, and the token response names the issued scope.

## 5. Operations

| Operation | Scope | Result |
|---|---|---|
| `GET /api/profile` | `sample-api.read` | HTTP 200 with `sub`, `client_id`, `scope`, and the binding (`DPoP` and `jkt`) of the access token. It returns no token. |
| `POST /api/notes` with a JSON body `{"text": "..."}` (at most 200 characters) | `sample-api.write` | HTTP 201 with the note and its time. The notes stay in memory for each `sub` until the API stops. |

## 6. Checks of each request

The API runs the checks in this order. The first failed check gives the response of section 7.

1. **Transport.** The access token comes only in the `Authorization` header with the `DPoP` scheme ([RFC 9449 section 7.1](https://www.rfc-editor.org/rfc/rfc9449.html#section-7.1)). The API rejects an `access_token` query or form parameter ([FAPI 2.0 section 5.3.4](https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.4) item 2). It rejects the `Bearer` scheme, because every access token that this API accepts is DPoP-bound. `POST /api/notes` reads its JSON body itself, so that a form body also reaches this check and is not rejected earlier with HTTP 415.
2. **Access token.** The token is a JWT with `typ` `at+jwt` ([RFC 9068 section 4](https://www.rfc-editor.org/rfc/rfc9068.html#section-4)) and `alg` PS256. The signature verifies with a key of `jwks_uri` from the discovery document of the configured issuer, after the issuer check of the discovery document. `iss` is the configured issuer. `aud` contains the API identifier. `exp` and `nbf` are valid with a clock skew of at most 10 seconds. An ID token fails, because its `typ` is `JWT` and its `aud` is the client ID.
3. **Binding in the token.** `cnf.jkt` is present. A token without `cnf`, or with only `cnf.x5t#S256`, fails: version 1 accepts only DPoP-bound tokens (section 11).
4. **DPoP proof** ([RFC 9449 section 4.3](https://www.rfc-editor.org/rfc/rfc9449.html#section-4.3)):
   - The request has exactly one `DPoP` header. Its value is a JWT with `typ` `dpop+jwt` and `alg` PS256.
   - The `jwk` header is a public key without private members, and the signature verifies with it.
   - `htm` is the method of the request. `htu` is the URL of the request without query and fragment, built from the configured public base URL, not from the `Host` or forwarding headers.
   - `iat` is at most 60 seconds old and at most 10 seconds in the future.
   - `jti` was not used before with the same key (section 8).
   - `ath` is the base64url-encoded SHA-256 hash of the access token.
   - The JWK thumbprint ([RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html)) of the proof key is `cnf.jkt` of the token.
5. **Revocation and current state.** The API calls `introspection_endpoint` of the discovery document for each request, with its own client assertion ([RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html)). The response must have `active` true, `token_type` `DPoP`, and `cnf.jkt` equal to the token. The API keeps no cache of the result. A production API can keep a short cache and accept that a revocation takes effect later.
6. **Access.** The `scope` of the token contains the scope of the operation ([FAPI 2.0 section 5.3.4](https://openid.net/specs/fapi-security-profile-2_0-final.html#section-5.3.4) item 4).

## 7. Error responses

Each error response has a `WWW-Authenticate: DPoP` challenge with `algs="PS256"` ([RFC 9449 section 7.1](https://www.rfc-editor.org/rfc/rfc9449.html#section-7.1)). The challenge and the body contain no value from the request. The log contains no token, proof, or assertion.

| Condition | Status | `error` |
|---|---|---|
| No `Authorization` header | 401 | None (the challenge has only `algs`, [RFC 6750 section 3.1](https://www.rfc-editor.org/rfc/rfc6750.html#section-3.1)) |
| Access token in a query or form parameter, or more than one `DPoP` header | 400 | `invalid_request` |
| `Bearer` scheme, a token that fails step 2 or 3, or a token that introspection reports as not active | 401 | `invalid_token` |
| Missing or invalid proof, a replayed proof, or a proof of another key | 401 | `invalid_dpop_proof` |
| The scope of the token does not contain the scope of the operation | 403 | `insufficient_scope`, with `scope` in the challenge |
| Introspection cannot be called, or the discovery document cannot be read or has another issuer | 503 | None. The API does not accept the token. |

## 8. Replay store and nonce

The API owns its replay store. It keeps each proof `jti` with the thumbprint of the proof key in memory until the end of the `iat` window (70 seconds). The sample runs as one instance. A deployment with more than one instance needs a shared store. The API does not send `DPoP-Nonce` ([RFC 9449 section 9](https://www.rfc-editor.org/rfc/rfc9449.html#section-9)); the `iat` window and the replay store limit the use of a stolen proof.

## 9. Settings

| Setting | Example | Meaning |
|---|---|---|
| `SampleApi:Issuer` | `https://dev.safewhere.local/runtime/oauth2` | The issuer. The API reads `{Issuer}/.well-known/openid-configuration` and rejects a document with another issuer. |
| `SampleApi:Audience` | `urn:kombit-oidc:sample-api` | The API identifier. |
| `SampleApi:PublicBaseUrl` | `https://localhost:44392` | The base of `htu`. Behind a reverse proxy, the public URL. |
| `SampleApi:ClientId` | `fapi-test-api` | The client ID of the API connection for introspection. |
| `SampleApi:AssertionSigningCertPath` and its password | User secrets | The key of the client assertion for introspection. Never in `appsettings.json`. |

## 10. Changes in the client sample

- The client requests `sample-api.read` and `sample-api.write` when the setting `SampleApi:BaseUrl` has a value.
- The home page gets the buttons **Call sample API** (`GET /api/profile`) and **Write note** (`POST /api/notes`). They send the access token with the `DPoP` scheme and a new proof with `ath`, and they show the result and the protocol trace.
- Fault injection gets the faults of the live scenarios: the `Bearer` scheme, a query token, the ID token as the access token, a proof of another key, a replayed proof, and a wrong `htm`, `htu`, or `ath`. The faults of UserInfo stay unchanged.

## 11. Out of scope in version 1

- Certificate-bound access tokens (`cnf.x5t#S256`). The API rejects them. Support needs a TLS client certificate at the API (Kestrel `ClientCertificateMode`) and a comparison with `x5t#S256` ([RFC 8705 section 3](https://www.rfc-editor.org/rfc/rfc8705.html#section-3)). A FAPI 2.0 connection that uses mTLS without DPoP cannot call this API.
- A resource server `DPoP-Nonce`.
- More than one instance, and persistence.
- Signed or encrypted responses of the API.

## 12. Tests

- **Unit tests** (`SampleApi.Tests`, 39 tests), one for each row of section 7, and a valid read and write. They include a query token, the ID token as the access token, another audience, an expired token, a token that introspection reports as not active, a proof of another key, a replayed proof, and a wrong `htm`, `htu`, or `ath`. `WebAppNetCore.Tests` (`SampleApiClientTests`) checks the requests of the client and each fault of section 10.
- **Live scenarios** in the kombit-oidc-fapi-test catalogue: a valid read and write with the fapi2 preset; each fault of section 10; a revoked access token; an access token of a connection without the API audience; and a read with a token that has only `sample-api.read` at `POST /api/notes`.

## 13. FAPI 2.0 section 5.3.4

| Item | Requirement | Section of this contract |
|---|---|---|
| 1 | Accept access tokens in the header | 6 step 1 |
| 2 | Do not accept access tokens in query parameters | 6 step 1, 7 |
| 3 | Verify validity, integrity, expiry, and revocation | 6 steps 2 and 5 |
| 4 | Verify that the authorization is sufficient, else return the RFC 6750 error | 6 step 6, 7 |
| 5 | Support and verify sender-constrained access tokens (DPoP or mTLS) | 6 steps 3 and 4, 8; mTLS is out of scope (11) |
