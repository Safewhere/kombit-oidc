# KOMBIT OIDC - Java Spring Boot Application

A Spring Boot application demonstrating OpenID Connect (OIDC) authentication with KOMBIT.

## Prerequisites

- **Java JDK 21+** - [Download here](https://adoptium.net/)
- **Maven** (optional - project includes Maven wrapper)

## Quick Start

### 1. Clone the Repository
```bash
git clone <repository-url>
cd java-oidc
```

### 2. Configure OIDC Settings

Edit `src/main/resources/application.yml` and update the OIDC configuration in **one place**:

```yaml
config:
  oidc:
    registration-id: oidc
    issuer-uri: https://your-oidc-provider.com
    client-id: your-client-id
    client-secret: your-client-secret
    redirect-uri: https://localhost:8000/oidc/callback
    scope: openid
    # Token authentication method: client_secret_post, client_secret_basic, or private_key_jwt
    token-auth-method: client_secret_post
    use-pkce: true
    authorization-endpoint-method: POST
    
    # ID token decryption certificate (if provider encrypts ID tokens)
    # Provider uses public key (use="enc") from jwks/jwks_uri to encrypt
    id-token-decryption-cert-path: ""
    id-token-decryption-cert-password: ""
    
    # JWT assertion signing certificate (required for private_key_jwt authentication)
    # Provider must have corresponding public certificate (use="sig") in jwks/jwks_uri
    # The JWT assertion is signed using RS256 algorithm with the certificate's private key
    jwt-assertion-signing-cert-path: ""
    jwt-assertion-signing-cert-password: ""
```

All OIDC settings are configured in the `config.oidc` section - no environment variables or duplicate configurations needed.

### 3. Run the Application

**Windows:**
```bash
.\mvnw.cmd spring-boot:run
```

**Linux/Mac:**
```bash
./mvnw spring-boot:run
```

### 4. Access the Application

Open your browser and navigate to:
```
https://localhost:8000
```

## Configuration

All OIDC configuration is centralized in `src/main/resources/application.yml` under the `config.oidc` section:

| Property | Description | Example |
|----------|-------------|---------|
| `issuer-uri` | OIDC provider's issuer URI | `https://your-provider.com` |
| `client-id` | OAuth2 client identifier | `your-client-id` |
| `client-secret` | OAuth2 client secret | `your-secret` |
| `redirect-uri` | Callback URL after authentication | `https://localhost:8000/oidc/callback` |
| `scope` | OAuth2 scopes | `openid` |
| `token-auth-method` | Token endpoint authentication method | `client_secret_post`, `client_secret_basic`, or `private_key_jwt` |
| `use-pkce` | Enable PKCE for authorization code flow | `true` |
| `authorization-endpoint-method` | HTTP method for authorization endpoint | `POST` |
| `id-token-decryption-cert-path` | Path to PKCS12 certificate for decrypting encrypted ID tokens | `path/to/decrypt-cert.p12` |
| `id-token-decryption-cert-password` | Password for the decryption certificate | `your-password` |
| `jwt-assertion-signing-cert-path` | Path to PKCS12 certificate for signing client_assertion (private_key_jwt only) | `path/to/sign-cert.p12` |
| `jwt-assertion-signing-cert-password` | Password for the signing certificate | `your-password` |

**Server Configuration:**
- **Port**: 8000 (HTTPS by default)

## Development

### Build the Project
```bash
.\mvnw.cmd clean package
```

### Run Tests
```bash
.\mvnw.cmd test
```

### Build JAR
```bash
.\mvnw.cmd clean package -DskipTests
java -jar target/kombit-oidc-*.jar
```

## SSL/TLS Configuration

The application runs on HTTPS by default. For development purposes, a self-signed certificate is acceptable. For production, configure a proper SSL certificate in `application.yml`.

## Troubleshooting

- **Port already in use**: Change the port in `application.yml` under `server.port`
- **SSL certificate issues**: For development, your browser may show security warnings for self-signed certificates - this is expected
- **OIDC connection issues**: Verify your issuer URI is correct and accessible
- **401 Unauthorized errors**: 
  - Verify your `client-id` and `client-secret` are correct
  - Check that `token-auth-method` matches your OIDC provider's requirements:
    - `client_secret_post`: Client credentials sent in request body (most common)
    - `client_secret_basic`: Client credentials sent in HTTP Basic Authentication header
    - `private_key_jwt`: Certificate-based authentication using signed JWT assertion (RS256 algorithm)
  - For `private_key_jwt`: Ensure your signing certificate is valid and not expired
- **Certificate authentication errors** (`invalid_client` with certificate issues): 
  - Verify `jwt-assertion-signing-cert-path` and `jwt-assertion-signing-cert-password` are correct
  - Ensure your certificate (`.p12` file) is not expired
  - Confirm the provider has your public certificate (use=\"sig\") in their jwks/jwks_uri
  - Contact your OIDC provider to obtain a new certificate if expired
- **Encrypted ID token errors**:
  - If provider encrypts ID tokens, configure `id-token-decryption-cert-path` and `id-token-decryption-cert-password`
  - Ensure the provider has your public key (use=\"enc\") in their jwks/jwks_uri
  - Verify the certificate corresponds to the public key used by the provider

## Project Structure

```
src/
├── main/
│   ├── java/kombit/oidc/
│   │   ├── config/          # OIDC and security configuration
│   │   ├── controller/      # Web controllers
│   │   ├── security/        # Security setup
│   │   ├── service/         # Business services
│   │   └── util/            # Utilities
│   └── resources/
│       ├── application.yml  # Main configuration
│       └── templates/       # HTML templates
└── test/                    # Test files
```
