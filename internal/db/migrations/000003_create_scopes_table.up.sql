CREATE TABLE IF NOT EXISTS scopes
(
    id           BIGSERIAL PRIMARY KEY,
    name         VARCHAR(255) NOT NULL,
    workspace_id BIGINT       NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,

    CONSTRAINT unique_name_workspace UNIQUE (name, workspace_id)
);

CREATE TABLE user_scopes
(
    user_id  INT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    scope_id INT NOT NULL REFERENCES scopes (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, scope_id)
);

CREATE UNIQUE INDEX idx_scopes_name_workspace ON scopes (name, workspace_id)