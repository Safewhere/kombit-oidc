# KOMBIT OIDC — Java Spring Boot Project Setup Guide

## Environment Setup

### Prerequisites
Ensure you have the following installed:
|------|----------|-------------|
| **Java (JDK)** | 21+ | Required to compile and run the project |
| **Maven** | 3.9+ | Build automation tool |
| **Git** | Latest | For cloning the repository |
| **IDE** | IntelliJ IDEA / VS Code | Recommended for development |

### Configure JAVA_HOME
**Windows**
```bash
$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-21"echo $env:Path = "$env:JAVA_HOME\bin;$env:Path"
```

**Linux/Mac**
```bash
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk
export PATH=$JAVA_HOME/bin:$PATH
```
#### Configure Environment
cd to root folder, open powershell and run: 
```bash
$env:OIDC_CLIENT_ID = "wpf-application"
$env:OIDC_CLIENT_SECRET = "secret-key-4567"
$env:OIDC_ISSUER="https://komitva322.safewhere.local/runtime/oauth2"
```
## SSL Configuration
This project uses HTTPS by default. SSL is configured in `application.properties`:

```properties
server.port=8000
server.ssl.enabled=true
server.ssl.key-store=classpath:keystore.p12
server.ssl.key-store-type=PKCS12
server.ssl.key-store-password=changeit
server.ssl.key-alias=local-ssl
```

If `keystore.p12` is missing, generate it manually:
```bash
keytool -genkeypair -alias local-ssl   -keyalg RSA -keysize 2048   -storetype PKCS12   -keystore src/main/resources/keystore.p12   -validity 3650
```

Then, run the app using:
```
https://localhost:8000
```

## Project Configuration
**Main Configuration File:** `src/main/resources/application.yml`

Typical configuration includes:
```yaml
spring:
  application:
    name: kombit-oidc
server:
  port: 8000

```
Ensure `application.yml`, `application.properties`, and `keystore.p12` are present under:
```
src/main/resources/
```
---

## Build & Run Project
### Run via Maven
```bash
mvn clean spring-boot:run
```
### Build JAR & Run
```bash
.\mvnw.cmd -DskipTests clean package
.\mvnw.cmd spring-boot:run
```
Access the application at:
```
https://localhost:8000
```

---
✅ **Quick Summary**
1. Install JDK 21, Maven, and Git.
2. Configure `JAVA_HOME` and verify paths.
3. Ensure SSL keystore (`keystore.p12`) exists or generate it.
4. Check configurations in `application.yml` and `application.properties`.
5. Run with `.\mvnw.cmd spring-boot:run` and open **https://localhost:8000**.