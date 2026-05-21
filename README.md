# ZenithSSO

ZenithSSO is a highly customizable Identity Provider (IdP) written in Go, following Clean Architecture principles. It implements OAuth2/OIDC standards, providing both REST API and gRPC interfaces for seamless integration.

## Configuration Reference (`config.yaml`)

| Parameter | Description | Default / Example |
| :--- | :--- | :--- |
| `grpc.port` | Port for the gRPC server | `50051` |
| `grpc.tls.enabled` | Enable TLS for gRPC | `true` |
| `grpc.tls.cert_path` | Path to TLS certificate | `./certs/server.crt` |
| `grpc.tls.key_path` | Path to TLS private key | `./certs/server.key` |
| `sso.issuer` | The base URL of the Identity Provider | `http://localhost:8080` |
| `server.secured` | Whether to use secure cookies (requires HTTPS) | `true` |
| `server.port` | Port for the HTTP server | `8080` |
| `datasource.url` | PostgreSQL database connection URL | `195.208.118.156:5432` |
| `datasource.db` | PostgreSQL database name | `auth` |
| `superuser.username` | Initial admin username | `admin` |
| `superuser.email` | Initial admin email | `admin@admin.com` |
| `superuser.password` | Initial admin password | `password` |
| `jwt.ttl.access` | Time-to-live for access tokens | `1` |
| `jwt.ttl.refresh` | Time-to-live for refresh tokens | `15` |
| `jwt.ttl.unit` | Time unit for TTL (`s`, `m`, `h`) | `m` |
| `jwt.cleanup.interval` | Interval for cleaning up expired tokens | `5` |
| `jwt.cleanup.unit` | Time unit for cleanup interval | `m` |
| `jwt.private_key_path` | Path to RSA private key for signing JWTs | `certs/private.pem` |
| `jwt.public_key_path` | Path to RSA public key for verifying JWTs | `certs/public.pem` |
| `ui.custom_dir` | (Optional) Path to a custom UI directory to override the embedded frontend. | `/path/to/custom/web` |

## Endpoints Reference

### REST API Endpoints
* `GET /.well-known/openid-configuration` - OIDC Discovery endpoint.
* `GET /api/v1/jwks` - Returns public keys for token verification.
* `POST /api/v1/register` - Register a new user account.
* `GET /api/v1/userinfo` - Get details of the authenticated user.
* `POST /api/v1/token` - Token exchange (authorization code, refresh token, password grants).
* `GET /api/v1/authorize` - Initiates the OAuth2 authorization flow.
* `POST /api/v1/authorize` - Processes user login during authorization flow.
* `GET /api/v1/consent` - Prompts user for consent.
* `POST /api/v1/consent` - Processes user consent.

### UI Routes
* `GET /login`, `POST /login` - Standalone user login.
* `POST /logout` - User logout.
* `GET /settings`, `POST /settings` - User profile and session management.
* `POST /settings/revoke-session` - Revokes a specific session.
* `GET /admin` - Admin panel for managing users and roles.
* `POST /admin/scopes` - Create a new role (scope).
* `POST /admin/users/scopes` - Assign a role to a user.

### gRPC Service (`AuthService`)
Defined in `api/proto/auth.proto`.
* `rpc Token` - Token exchange operations.
* `rpc Authorize` - Headless authorization for trusted clients.
* `rpc UserInfo` - Retrieve user information.
* `rpc Revoke` - Revoke an access or refresh token.
* `rpc Sessions` - List active sessions for a user.
* `rpc RevokeSession` - Revoke a specific session or all except current.

## Customizing the UI

ZenithSSO comes with a built-in embedded UI. However, you can easily override the HTML templates and static assets (CSS/JS) without recompiling the application.

1. **Create your custom directory structure:**
   Create a folder anywhere on your server, e.g., `/opt/zenithsso/custom_ui`. Inside it, create two subdirectories: `templates` and `static`.
   ```bash
   mkdir -p custom_ui/templates
   mkdir -p custom_ui/static/css
   ```

2. **Add your custom files:**
   Place your modified HTML files in `templates/` (e.g., `login.html`, `admin.html`). Place your CSS files in `static/css/` (e.g., `style.css`). Make sure you retain the specific filenames expected by the server.

3. **Update `config.yaml`:**
   Point the server to your new directory using the `ui.custom_dir` parameter:
   ```yaml
   ui:
     custom_dir: "/opt/zenithsso/custom_ui"
   ```

When restarted, ZenithSSO will serve your custom files instead of the embedded ones!
