-- Additive, transactional migration. Runtime holds the migration advisory lock.
CREATE TABLE accounts (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, bio TEXT NOT NULL,
    declared_dot BOOLEAN NOT NULL CHECK (declared_dot), declaration_version INTEGER NOT NULL,
    disabled BOOLEAN NOT NULL DEFAULT FALSE, created TEXT NOT NULL
);
CREATE TABLE invitations (
    digest TEXT PRIMARY KEY, label TEXT NOT NULL, expires BIGINT NOT NULL,
    used_by TEXT REFERENCES accounts(id), created TEXT NOT NULL
);
CREATE TABLE account_secrets (
    digest TEXT PRIMARY KEY, account TEXT NOT NULL REFERENCES accounts(id),
    kind TEXT NOT NULL CHECK (kind IN ('access','recovery')),
    expires BIGINT NOT NULL, revoked BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX account_secrets_account ON account_secrets(account);
CREATE TABLE conversations (
    id TEXT PRIMARY KEY, visibility TEXT NOT NULL CHECK (visibility IN ('public','private')),
    title TEXT NOT NULL, creator TEXT NOT NULL REFERENCES accounts(id), created TEXT NOT NULL
);
CREATE TABLE participants (
    conversation TEXT NOT NULL REFERENCES conversations(id), account TEXT NOT NULL REFERENCES accounts(id),
    PRIMARY KEY (conversation,account)
);
CREATE INDEX participants_account ON participants(account,conversation);
CREATE TABLE entries (
    id BIGSERIAL PRIMARY KEY, conversation TEXT NOT NULL REFERENCES conversations(id),
    author TEXT NOT NULL REFERENCES accounts(id), body TEXT NOT NULL, created TEXT NOT NULL,
    redacted BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX entries_conversation ON entries(conversation,id);
CREATE TABLE events (
    id BIGSERIAL PRIMARY KEY, conversation TEXT NOT NULL REFERENCES conversations(id),
    entry BIGINT NOT NULL REFERENCES entries(id), kind TEXT NOT NULL,
    created TEXT NOT NULL
);
CREATE INDEX events_conversation ON events(conversation,id);
CREATE TABLE write_requests (
    actor TEXT NOT NULL REFERENCES accounts(id), key TEXT NOT NULL,
    signature TEXT NOT NULL, status INTEGER NOT NULL, response JSONB NOT NULL,
    PRIMARY KEY(actor,key)
);
CREATE TABLE audit (
    id BIGSERIAL PRIMARY KEY, action TEXT NOT NULL, subject TEXT NOT NULL, created TEXT NOT NULL
);
CREATE TABLE rate_windows (
    actor TEXT PRIMARY KEY, window_start BIGINT NOT NULL, count INTEGER NOT NULL
);
CREATE TABLE blocks (
    blocker TEXT NOT NULL REFERENCES accounts(id), blocked TEXT NOT NULL REFERENCES accounts(id),
    PRIMARY KEY(blocker,blocked), CHECK(blocker<>blocked)
);
