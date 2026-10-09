-- Webhook transport state is intentionally separate from the durable inbox ACK.
-- Signing secrets are authenticated ciphertext; the encryption key is operator-held.
CREATE TABLE mcp_event_subscriptions (
    id TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL REFERENCES oauth_grants(id) ON DELETE CASCADE,
    account TEXT NOT NULL REFERENCES accounts(id),
    inbox_name TEXT NOT NULL,
    inbox_generation TEXT NOT NULL REFERENCES notification_subscriptions(generation) ON DELETE CASCADE,
    callback_url TEXT NOT NULL,
    secret_cipher BYTEA NOT NULL,
    previous_secret_cipher BYTEA,
    previous_secret_until BIGINT NOT NULL DEFAULT 0,
    expires BIGINT NOT NULL,
    transport_cursor BIGINT NOT NULL CHECK (transport_cursor >= 0),
    suspended BOOLEAN NOT NULL DEFAULT FALSE,
    last_error TEXT,
    created TEXT NOT NULL,
    UNIQUE(grant_id, callback_url, inbox_generation)
);
CREATE INDEX mcp_event_subscriptions_account ON mcp_event_subscriptions(account);
CREATE TABLE mcp_callback_verifications (
    grant_id TEXT NOT NULL REFERENCES oauth_grants(id) ON DELETE CASCADE,
    callback_url TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    verified_until BIGINT NOT NULL,
    PRIMARY KEY(grant_id,callback_url)
);
-- At most one coalesced pending occurrence per subscription, including retries.
CREATE TABLE mcp_event_outbox (
    subscription_id TEXT PRIMARY KEY REFERENCES mcp_event_subscriptions(id) ON DELETE CASCADE,
    event_id TEXT NOT NULL UNIQUE,
    transport_cursor BIGINT NOT NULL CHECK (transport_cursor >= 0),
    body TEXT NOT NULL CHECK (octet_length(body) <= 262144),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 8),
    next_attempt BIGINT NOT NULL,
    lease_id TEXT,
    lease_until BIGINT NOT NULL DEFAULT 0,
    expires BIGINT NOT NULL,
    created TEXT NOT NULL
);
CREATE INDEX mcp_event_outbox_due ON mcp_event_outbox(next_attempt);
