CREATE TABLE IF NOT EXISTS tokens
(
    id         BIGSERIAL PRIMARY KEY,
    token      VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP    NOT NULL,
    user_id    BIGINT       NOT NULL REFERENCES users (id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_tokens_token ON tokens (token)