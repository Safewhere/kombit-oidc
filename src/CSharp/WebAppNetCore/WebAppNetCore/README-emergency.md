# Emergency access PoC
## Current PoC configuration (October 23, 2026)

Configure a matching `ApiKey` string directly in each Identify `Clients[]` entry and in that client's settings. For example, use `"ApiKey": "oidc-poc-key"` on both OIDC sides and a different `"ApiKey": "saml-poc-key"` on both SAML sides. Plain nonempty text or a GUID is supported, up to 512 characters without control characters. No issuer-key environment variables are required. Existing environment-variable settings are supported only as a legacy fallback when ApiKey is absent. Do not print live keys in diagnostics.

The issuer defaults and upper bounds are RecordLifetime=`1.00:00:00` (24 hours), EnrollmentLifetime=`01:00:00` (1 hour), and CredentialLifetime=`30.00:00:00` (30 days). The enrollment deadline is capped by its source record's expiry. Client preparation is also bounded by normal-login validity. Both clients accept the corresponding 30-day credentials; revocations are retained for 30 days plus five minutes. WebAuthn proof challenges remain short-lived. Deploy issuer and client updates together before issuing longer credentials.

OIDC uses the normal ID token; SAML uses the normal assertion. Normal protocol, assurance, identity, application, and repeated claims are retained in the credential snapshot and emergency principal. Their original exp/iat/iss/acr values describe the original login; the emergency session has its own independently enforced expiry and authentication type. Source claims cannot replace internal `emergency*` or `local_*` session controls. General size, signature, issuer, audience, and input validation remain enforced. Renew after a fresh normal login to obtain a new snapshot. Attributes absent from the ID token/assertion cannot be invented by the client.


Emergency support is disabled by default. This implementation belongs to the OIDC example. It shares no source, project, browser bundle, or implementation package with the SAML example. It uses public Fido2 4.1.0 and .NET 10. Identify keeps Safewhere.Fido2. The current key-protection baseline is Windows.

The [local setup record](README-emergency-setup-record.md) records the actual configuration steps, code correction, verification, and remaining browser actions for the dev520 deployment.

## Configure an isolated deployment

There are two different JSON formats. Identify reads its own external issuer settings file, which has top-level `Issuer`, `StorageDirectory`, and `Clients`. This OIDC application binds an `EmergencyCredential` section from ASP.NET Core configuration. Do not point Identify at this sample's `emergency-settings.example.json`.

The sample does **not** automatically load a file named `emergency-settings.json`. Copying that file outside the application is preparation only. Step 5 below shows how to apply its section to an IIS deployment.

### 1. Verify normal login and record the identifiers

Use a separate HTTPS host for each UserSystem. The RP ID is the exact host name, without a scheme, path, or port. Different ports on one host do not give separate RP IDs.

For example, this local deployment uses:

| Setting | Value |
|---|---|
| Identify tenant | `https://dev520.safewhere.local` |
| Identify Runtime API base | `https://dev520.safewhere.local/runtime/` |
| Normal OIDC issuer | `https://dev520.safewhere.local/runtime/oauth2` |
| Emergency issuer | `https://dev520.safewhere.local/runtime/emergency` |
| UserSystem origin | `https://kombitoidc.safewhere.local` |
| UserSystem RP ID | `kombitoidc.safewhere.local` |
| Sample deployment | `C:\inetpub\wwwroot\kombitoidc` |
| Emergency audience | `urn:emergency:oidc-example` |

Read the normal client ID and issuer from the deployed application's `OpenIdConnectOptions`. Get the protocol connection GUID from that connection in Identify Admin. The GUID and the OIDC client ID are different values. Verify the normal issuer against the tenant's OIDC discovery document. Normal login must already work.

### 2. Create the encryption key once

Run the key tool with PowerShell 7.2 or later. Use a **new absolute local directory outside all repositories and web roots**. Include the actual application-pool identity:

```powershell
./New-EmergencyKey.ps1 -OutputDirectory C:\ProgramData\SafewhereSamples\OidcEmergency -Audience urn:emergency:oidc-example -ApplicationIdentity 'IIS APPPOOL\kombitoidc.safewhere.local'
```

The tool restricts the directory ACL and creates `decryption-key.bin` and `encryption-public.jwk.json`. If these already exist, continue with them; do not regenerate the key. Keep the same audience: it is part of the DPAPI protection purpose. The script does not enable the feature or create TLS credentials.

### 3. Configure Identify's issuer

Create a separate external directory for Identify, for example `C:\ProgramData\Safewhere\EmergencyIssuer\dev520`. Give the Identify Runtime application-pool identity read access to its settings and modify access to a `state` subdirectory. Do not grant Identify access to the sample's private decryption key.

Use Identify's `docs/features/US39805/issuer-settings.example.json` as the template. Configure one OIDC client with these mappings:

| Identify field | Source |
|---|---|
| `Issuer` | Emergency issuer from step 1 |
| `StorageDirectory` | Identify's external `state` directory |
| `ClientId` | A unique emergency-client identifier, such as `oidc-example` |
| `NormalProtocol` | `oidc` |
| `NormalProtocolIdentifier` | The deployed sample's normal OIDC client ID |
| `ProtocolConnectionId` | The corresponding Identify connection GUID |
| `NormalLoginIssuer` | Normal issuer from step 1 |
| `EmergencyAudience` | Audience used by the key tool |
| `Origin`, `RelyingPartyId` | UserSystem origin and RP ID from step 1 |
| `EncryptionKeyId`, `EncryptionModulus`, `EncryptionExponent` | `kid`, `n`, and `e` from `encryption-public.jwk.json` |
| `ApiKey` | Same value as `EmergencyCredential.ApiKey` in this sample |
| `IssuanceEnabled` | `true` |
| `AllowedClaimTypes` | Optional legacy issuer setting; all normal ID-token claims are captured |
| `PreserveNormalClaims` | `true`, so every claim in the normal ID token is signed into the emergency credential |

Remove unused example clients. Every listed client is validated, even if its issuance switch is false. Each client needs a distinct encryption key, audience, RP ID, and backend secret.

Set these entries in Identify Runtime's effective `<appSettings>` configuration. Update an existing entry instead of adding a duplicate:

```xml
<add key="EmergencyIssuer.Enabled" value="true" />
<add key="EmergencyIssuer.SettingsFile"
     value="C:\ProgramData\Safewhere\EmergencyIssuer\dev520\issuer-settings.json" />
```

For an installed tenant, this is the Runtime configuration under that tenant, not the source repository's Web.config. Check external configuration overrides. Identify supplies `TenantId` from its own tenant configuration.

### 4. Configure the matching API key

Set `EmergencyCredential.ApiKey` to the same plain text or GUID as the issuer client entry. No IIS environment variable is needed. This is separate from the normal OIDC client secret.

### 5. Apply the sample settings

Copy [emergency-settings.example.json](emergency-settings.example.json) outside the repository. Replace every placeholder. `IssuerBaseUrl` is the Runtime API base and must end in `/`. `Issuer` is the exact EC issuer, while `NormalIssuer` is the normal OIDC issuer. Set the origin without a trailing slash. Use the `kid` from the generated public JWK as `EncryptionKeyId`.

Keep these sample paths under the restricted directory created in step 2:

```text
StorageDirectory:       C:\ProgramData\SafewhereSamples\OidcEmergency\state
ProtectionKeysDirectory: C:\ProgramData\SafewhereSamples\OidcEmergency\protection
EncryptionPrivateKeyFile: C:\ProgramData\SafewhereSamples\OidcEmergency\decryption-key.bin
TrustedSigningKeysFile: C:\ProgramData\SafewhereSamples\OidcEmergency\issuer-signing-keys.json
```

For IIS, merge the external file's `EmergencyCredential` object into the **deployed** `appsettings.json`, preserving every other section. For example, run this in an elevated PowerShell session after selecting your paths:

```powershell
$externalSettings = 'C:\ProgramData\SafewhereSamples\OidcEmergency\emergency-settings.json'
$deployedSettings = 'C:\inetpub\wwwroot\kombitoidc\appsettings.json'
$backupDirectory = 'C:\ProgramData\SafewhereSamples\OidcEmergency\backups'
New-Item -ItemType Directory -Force -Path $backupDirectory | Out-Null
Copy-Item -LiteralPath $deployedSettings -Destination (Join-Path $backupDirectory ('appsettings-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json'))
$external = Get-Content -LiteralPath $externalSettings -Raw | ConvertFrom-Json
$deployed = Get-Content -LiteralPath $deployedSettings -Raw | ConvertFrom-Json
$external.EmergencyCredential.Enabled = $false
$deployed | Add-Member -MemberType NoteProperty -Name EmergencyCredential -Value $external.EmergencyCredential -Force
[IO.File]::WriteAllText($deployedSettings, ($deployed | ConvertTo-Json -Depth 32), [Text.UTF8Encoding]::new($false))
```

This initially keeps support disabled. Do not print the whole deployed JSON: other sections may contain normal-login secrets. Keep the backup outside the web root and repository. Check `appsettings.Production.json`, IIS environment variables, and other configured providers for overrides. Preserve the emergency section in future deployments.

For local Development only, the alternative is user secrets:

```powershell
Get-Content -Raw <external-settings-file> | dotnet user-secrets set --project WebAppNetCore.csproj
```

User secrets configured for your interactive account are not a substitute for configuration of a deployed IIS application.

### 6. Restart Identify and establish signing-key trust

Stop the Identify Runtime pool, wait for its old worker to exit, and start it. Do not replace this with an overlapping recycle when the issuer owns its state file.

Download the emergency public signing keys over certificate-validated HTTPS to the sample's configured `TrustedSigningKeysFile`:

```powershell
Invoke-WebRequest -Uri 'https://dev520.safewhere.local/runtime/emergency/signing-keys' `
    -OutFile 'C:\ProgramData\SafewhereSamples\OidcEmergency\issuer-signing-keys.json'
```

The response must be HTTP 200 with a `keys` array containing the emergency signing key. This is a different key from both the sample's RSA encryption key and Identify's normal OIDC signing keys. A 503 response means issuer configuration or state is unavailable; check the Runtime Error log. Do not save an error response as the trust file or bypass certificate validation. The emergency HTTP client does not use the normal demo's debug certificate-validation bypass.

### 7. Enable sample support

After the issuer, trust file, directory permissions, and process secrets are ready, set the deployed `EmergencyCredential.Enabled` value to `true`. Stop and start the sample pool. Keep `state` and `protection` persistent and run one worker process for this PoC.

Open `/emergency/login` to check the local setup. Emergency login is available as soon as support is enabled; there is no separate acceptance switch. A browser can log in once it has completed preparation. Log out and perform a fresh normal login after enabling the issuer: old login sessions have no newly captured preparation record.

Private JWE keys use machine-bound DPAPI with an audience-specific purpose. The emergency Data Protection key ring also uses DPAPI on Windows. Retain the key, state, and protection directories and their ACLs. Copying them to another machine is not a supported recovery procedure. No secret or private key belongs in source control.

### Troubleshooting

| Symptom | Check |
|---|---|
| Normal login works, emergency feature is unavailable | Normal login has separate configuration. Confirm the full `EmergencyCredential` section is loaded, not only `Enabled`. |
| Identify returns `503 issuer_unavailable` | Check `EmergencyIssuer.SettingsFile`, the top-level Identify JSON format, all client placeholders, process secret availability, storage permissions, and the Runtime Error log. |
| Sample returns `503 emergency_unavailable` | Check required options, DPAPI audience/machine, key and trust files, directory permissions, and process secrets. Restart after correcting initialization failures. |
| Enrollment needs a new login | Perform a new normal login after issuer setup. Its ID token must contain `iss`, `sub`, `jti`, and `iat`; the record expires after ten minutes. |
| No eligible security key | Use an authenticator with user verification and without backup eligibility. A synced passkey can be rejected by this PoC policy. |
| Client configuration changed after state was created | Follow Identify's documented client-recovery procedure. Do not delete state files to force a settings change. |

## Use the feature

- After normal login, open **Prepare emergency access**. The accepted ID token needs `iss`, `sub`, `jti`, and `iat`. Preparation evidence lasts ten minutes. Userinfo-only claims do not become emergency authorization.
- Choose **Prepare this browser**. Finish registration, IndexedDB storage/read-back, and the separate possession check. Readiness requires all three. Use a key with user verification and without passkey backup.
- During an outage, use `/emergency/login`. A prepared browser can log in immediately; no operator approval is needed. Emergency sessions end within eight hours and before EC expiry. Login, home, and local logout use no Identify request, OP iframe, or normal token operation.
- Preparation and renewal synchronize issuer state and signing trust while online. A changed issuer `state_id` blocks old credentials and sessions and requires new preparation. Failed trust refresh remains blocked across restart. Offline login does not perform this synchronization.
- Renew after a newer normal login. The old EC stays active until its replacement is stored and confirmed. Pending entries can be confirmed later. Failed delivery can leave an issuer binding that needs recovery.
- Remove keys locally first. Failed issuer reports remain queued. The next preparation or renewal refreshes trust, applies revocations, and retries removals. There is no automatic network polling in the emergency flow.
- Removing a key, or an issuer revocation applied during synchronization, also ends current sessions for that key.

To disable support, set only `EmergencyCredential.Enabled=false` and restart while retaining the external storage-path configuration. Startup marks existing state so that current emergency sessions end, without loading private keys. Removing the path configuration is not the supported disable procedure.

## Build and check

From `src/CSharp/WebAppNetCore`:

```powershell
dotnet build ./WebAppNetCore/WebAppNetCore.csproj --disable-build-servers /m:1 /p:UseSharedCompilation=false /p:UseRazorBuildServer=false
dotnet test ./WebAppNetCore.Emergency.Tests/WebAppNetCore.Emergency.Tests.csproj --disable-build-servers /m:1 /p:UseSharedCompilation=false /p:UseRazorBuildServer=false
dotnet build-server shutdown
```

The current emergency suite passes 57 tests, including issuer-state changes, legacy state recovery, failed trust refresh across restart, and concurrent trust-refresh races. Tests generate disposable keys outside the repository. They cover credential profiles, both WebAuthn algorithms, replay/counters, lifecycle state, expiry, renewal, offline removal, restart, HTTP guards, and OIDC callback isolation. Browser checks used the actual app at a virtual base path and a virtual authenticator. Preparation used synthetic accepted-login evidence with credentials issued by the actual Identify implementation. This is not a completed normal federation run against a configured Identify tenant.

## PoC limits

This is one process with bounded local state. Protection does not prevent a trusted host administrator from restoring old state. There is no trusted hardware-attestation policy, multi-node coordination, automated encryption-key rotation, or rollback-proof recovery. Issuer-state recovery blocks previous credentials and requires new preparation. Offline authorization can be stale. Browser data deletion loses preparation.

Every claim from the normal ID token is kept, including all roles. Normal assurance, tokens, session IDs, and reserved markers are excluded. The OIDC example grants no basic privilege XML. Existing normal-demo token diagnostics remain outside emergency behavior. Real normal SSO/logout, physical authenticators, other deployment combinations, and production dependency review still need evidence.

## PoC: inspect Identify endpoint results

Expand **Identify endpoint results (PoC)** on any emergency page. Perform preparation, renewal, or key removal to see the backend calls made by that action. Each entry shows the HTTP method, endpoint template, HTTP status, elapsed milliseconds, and a redacted result summary. Network failures and rejected response bodies are distinguished from HTTP failures. A successful issuer response is not proof that local credential validation or preparation completed.

Local operations such as authenticator possession checks, emergency login, and local logout show **no Identify endpoint called** when their backend request makes no issuer call. Viewing the panel never contacts Identify or repeats an operation.

The panel keeps the latest 40 entries in this tab's session storage, including across redirects to the emergency home page. Each action includes at most its latest 8 issuer calls (synchronization may paginate). **Clear displayed history** removes only this display history; it does not remove credentials or revoke keys. If session storage is unavailable, the panel works until navigation. Existing calls from before this version was loaded are not reconstructed.

Results contain no request/response bodies, API keys, token references, emergency credential values, enrollment IDs, binding IDs, subjects, or personal claims. HTTP statuses and fixed summaries are returned only on the originating request via the bounded `X-Emergency-Issuer-Calls` response header. This is a demonstration aid, not a durable audit log.

## Claims from normal login

The emergency session gets the claims from the normal login's ID token. Identify captures the claims it issued in the normal OIDC ID token and signs them into the emergency credential's `claims_snapshot`; set `PreserveNormalClaims: true` on the matching Identify issuer client so that all of them are included. The browser never supplies a claims list. The sample has no claim-type or role allowlist: it projects every snapshot claim into the emergency principal, preserving claim types, values, value types, and repeated claims. It does not fetch current claims during offline login.

Normal-login claim types and values, including protocol metadata and assurance claims, are preserved as historical snapshot data. Local `emergency*` and `local_*` control claims remain reserved so a source token cannot override the active session identifier or expiry. The emergency session authenticates and expires independently of the original token. Roles and SAML BPP claims are not allowlisted or rewritten.

Claims are fixed when the credential is issued. Role or attribute changes after preparation are not reflected until renewal. Attributes that were never present in the ID token cannot be invented. Access-token and UserInfo claims are not used.

## Remove a local key

**Remove key locally** deletes the binding and all associated credential versions from the client registry and this browser's IndexedDB, including renewed/replaced copies. It ends existing sessions for that binding and rejects replay of its previously issued credentials. The row disappears rather than becoming Blocked. An offline removal is immediately effective and survives restart; only the binding identifier needed to retry issuer revocation is retained in the internal queue. Other browsers may retain stale copies, but the server rejects them. This removes the application registration; it does not erase a hardware authenticator's internal key through WebAuthn.

The browser-only **Forget browser copy** action has been removed: it could strand an active issuer registration and prevent the same authenticator from being prepared again. If browser storage is lost, obtain a fresh normal login and open the preparation page. Registered keys without a browser copy are now shown as **Browser copy missing**, with **Remove key locally** available. Remove the old registration, let issuer revocation synchronize, and then prepare the authenticator again. Removal ends that binding's emergency sessions in every browser. If the client registry itself was lost (not only browser storage), an issuer administrator must revoke the orphaned binding. Clearing browser storage alone never unregisters a key.

The preparation page shows exactly one next action: **Prepare this browser** while a fresh unused normal-login record is eligible, or **Get a new normal login for preparation or renewal** otherwise. Starting preparation/renewal consumes that record, so the page switches back to the login action. Pending credentials can still be confirmed using their own key-check control.

## Trace an emergency request

The client generates a new `X-Emergency-Reference` response header for each emergency request. Controller error JSON also includes `reference_id`, and the browser error message displays it. Copy that reference to find the matching server events; it is an opaque diagnostic ID, not a login token.

The logger category is `WebAppNetCore.EmergencyCredential.Diagnostics`. The example configuration enables Information for that category on the Console and Debug providers while retaining Warning for other categories. When merging configuration into IIS, preserve that category override under both `Logging:Console:LogLevel` and `Logging:Debug:LogLevel`; any other active logging provider needs the same category level.

Look for `request_started`, `issuer_calls`, `action_failed`, and `request_completed` with the same reference. Completion includes HTTP status and elapsed milliseconds. Issuer-call summaries include normalized endpoint templates, statuses and durations, so an HTTP 502 can be traced to the actual upstream response. Normal-login capture emits `normal_login_captured`, `normal_login_capture_skipped`, or `normal_login_capture_failed`; those callback events have their own request reference.

The logs use the application's configured ASP.NET Core logging providers. Debug output is visible in the debugger and Console output in the hosting process. This change does not create a file logger. On IIS, use your configured persistent logging sink, or temporarily enable ASP.NET Core Module stdout logging to a restricted writable location when troubleshooting; disable temporary stdout logging afterward and manage retention. If Information events are absent, check provider-specific log-level overrides before retrying the flow.

Events omit request bodies, query values, cookies, API keys, token/credential strings, binding IDs, claim values, raw exception messages and source paths. Failure records include bounded exception types/HResults, including initialization causes. Logging failures are swallowed so authentication behavior is preserved. A successful request with a failed issuer call may represent an offline-safe local operation with revocation queued; inspect the endpoint and issuer summary together.

## Authenticator policy compatibility

The current issuer and both clients use `poc-up`: presence is required, verification is preferred, and valid backup-eligible/backed-up passkeys are accepted. A backup-state bit without backup eligibility is rejected. Signature, origin/RP, one-use challenge, credential ownership, and counter checks remain enforced. Credentials labeled with the older `poc-uv-nonbackup` policy must be renewed to the current policy; they are not silently reinterpreted.


## Single-tenant configuration layout

Use `C:\ProgramData\SafewhereSamples\OidcEmergency` directly. Do not add a tenant subfolder. Keep these files outside the deployed website and source control:

```text
OidcEmergency/
  emergency-settings.json
  decryption-key.bin
  encryption-public.jwk.json
  issuer-signing-keys.json
  state/
  backups/
  protection/  (ASP.NET Core data-protection keys)
```

OIDC keeps the `EmergencyCredential` wrapper in this JSON. Apply that section to deployed `appsettings.json` using step 5 above; the external JSON is the setup source, not an automatically loaded configuration provider.

To migrate an existing installation, stop the client pool, back up its settings and protected state, and move the existing files rather than generating new keys. Update every absolute path in the settings and the deployed configuration, then restart the pool. Preserve directory ACLs and the existing machine/data-protection keys. Do not reset state, change the emergency audience, or run the key-generation script over the existing installation. Keep old files only in `backups`, not as a second live configuration. No Identify redeployment or issuer configuration change is needed for this directory move.

Regression check: prepare a key, simulate losing its browser storage, then perform a fresh normal login. The preparation page must show one **Browser copy missing** row per binding, including when it has several renewed versions. **Remove key locally** must report revocation to Identify and remove the row. Only then enroll the same authenticator again. A failed removal request must leave browser data untouched. The emergency-login page must never offer browser-only deletion.


### Active keys on emergency login

The emergency-login screen displays only browser-stored keys that the client registry currently accepts as active and unexpired. Pending, replaced, blocked, removed, expired, and invalid credentials are hidden. The page checks each stored credential through a read-only local status endpoint; it does not contact Identify, require normal login, or create a WebAuthn challenge. Preparation still shows management and pending-confirmation controls. Login rechecks eligibility when the key is used. Revocations unknown to the offline client cannot be detected until synchronization.

Deploy the updated client assemblies and browser script together: the script now requires the local login-status endpoint. No Identify redeployment or settings change is needed. Hard-refresh the emergency-login page after deployment.


Configuration-fingerprint checks are no longer used in this PoC. Remove `ResetPreviousConfigurationHash` from old Identify settings. Settings changes do not automatically revoke existing registrations. Protected-state integrity and protocol/token validation remain enforced; keep existing data-protection keys and the audience used to protect state.
