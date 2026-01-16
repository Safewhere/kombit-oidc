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
    post-logout-redirect-uri: https://localhost:8000/
    scope: openid
    token-auth-method: client_secret_post  # Use 'private_key_jwt' for certificate auth or 'client_secret_post' for secret
    use-pkce: true
    authorization-endpoint-method: POST
    # Optional: Required only for private_key_jwt authentication:
    jwt-signing-keystore-path: ""
    jwt-signing-keystore-password: ""
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
| `post-logout-redirect-uri` | Redirect URL after logout | `https://localhost:8000/` |
| `scope` | OAuth2 scopes | `openid` |
| `token-auth-method` | Token endpoint authentication method | `client_secret_post` or `private_key_jwt` |
| `use-pkce` | Enable PKCE for authorization code flow | `true` |
| `authorization-endpoint-method` | HTTP method for authorization endpoint | `POST` |
| `jwt-signing-keystore-path` | Path to PKCS12 certificate (for private_key_jwt) | `path/to/cert.p12` |
| `jwt-signing-keystore-password` | Password for the keystore | `your-password` |

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
  - Check that `token-auth-method` matches your OIDC provider's requirements
  - Some providers (like KOMBIT) may require `private_key_jwt` with a valid certificate
- **Certificate authentication errors** (`invalid_client` with certificate expired): 
  - Change `token-auth-method` to `private_key_jwt`
  - Ensure your certificate (`.p12` file) is not expired
  - Set `jwt-signing-keystore-path` and `jwt-signing-keystore-password`
  - Contact your OIDC provider to obtain a new certificate if expired

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

## License

[Add your license here]