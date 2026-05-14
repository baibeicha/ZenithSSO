CREATE TABLE IF NOT EXISTS clients
(
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id          VARCHAR(255) UNIQUE NOT NULL,
    client_secret_hash VARCHAR(255)        NOT NULL,
    redirect_uris      JSONB               NOT NULL
);

CREATE INDEX idx_clients_client_id ON clients (client_id);

CREATE TABLE IF NOT EXISTS auth_codes
(
    code                  VARCHAR(255) PRIMARY KEY,
    client_id             VARCHAR(255) NOT NULL REFERENCES clients (client_id) ON DELETE CASCADE,
    user_id               BIGINT       NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    redirect_uri          TEXT         NOT NULL,
    code_challenge        VARCHAR(255) NOT NULL,
    code_challenge_method VARCHAR(50)  NOT NULL,
    expires_at            TIMESTAMP    NOT NULL
);

CREATE INDEX idx_auth_codes_code ON auth_codes (code);