-- Additive OAuth state. Secrets are random 256-bit values stored only as SHA-256 digests.
-- Consent binds one existing account to a configured public client and exact MCP resource.
CREATE TABLE oauth_link_tickets (
    digest TEXT PRIMARY KEY,
    account TEXT NOT NULL REFERENCES accounts(id),
    issuer TEXT NOT NULL, resource TEXT NOT NULL, client_id TEXT NOT NULL,
    expires BIGINT NOT NULL, used BOOLEAN NOT NULL DEFAULT FALSE,
    created TEXT NOT NULL
);
CREATE INDEX oauth_link_tickets_account ON oauth_link_tickets(account);
CREATE TABLE oauth_requests (
    digest TEXT PRIMARY KEY, browser_digest TEXT NOT NULL, csrf_digest TEXT NOT NULL,
    issuer TEXT NOT NULL, resource TEXT NOT NULL, client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL, scopes TEXT[] NOT NULL,
    state TEXT NOT NULL, code_challenge TEXT NOT NULL,
    account TEXT REFERENCES accounts(id),
    expires BIGINT NOT NULL, used BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX oauth_requests_expiry ON oauth_requests(expires);
CREATE TABLE oauth_grants (
    id TEXT PRIMARY KEY, account TEXT NOT NULL REFERENCES accounts(id),
    issuer TEXT NOT NULL, resource TEXT NOT NULL, client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL, scopes TEXT[] NOT NULL,
    expires BIGINT NOT NULL, revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created TEXT NOT NULL
);
CREATE INDEX oauth_grants_account ON oauth_grants(account);
CREATE TABLE oauth_codes (
    digest TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES oauth_grants(id) ON DELETE CASCADE,
    code_challenge TEXT NOT NULL, expires BIGINT NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE TABLE oauth_tokens (
    digest TEXT PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES oauth_grants(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('access','refresh')),
    expires BIGINT NOT NULL, used BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX oauth_tokens_grant ON oauth_tokens(grant_id);
