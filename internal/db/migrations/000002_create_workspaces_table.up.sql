CREATE TABLE IF NOT EXISTS workspaces
(
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL
);

CREATE UNIQUE INDEX idx_workspaces_name ON workspaces(name);