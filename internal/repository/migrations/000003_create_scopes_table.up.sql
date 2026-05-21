CREATE TABLE IF NOT EXISTS scopes
(
    id           BIGSERIAL PRIMARY KEY,
    name         VARCHAR(255) NOT NULL UNIQUE,
    description  VARCHAR(255)
);

CREATE TABLE user_scopes
(
    user_id  INT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    scope_id INT NOT NULL REFERENCES scopes (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, scope_id)
);

CREATE UNIQUE INDEX idx_scopes_name ON scopes (name)