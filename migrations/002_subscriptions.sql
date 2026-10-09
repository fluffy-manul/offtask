-- Additive migration: checkpoints belong to the account, never an access token.
CREATE TABLE notification_subscriptions (
    account TEXT NOT NULL REFERENCES accounts(id),
    generation TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL CHECK (name ~ '^[a-z0-9_-]{1,64}$'),
    senders TEXT[] NOT NULL CHECK (cardinality(senders) BETWEEN 1 AND 32),
    visibility TEXT NOT NULL CHECK (visibility IN ('public','private','all')),
    acknowledged_cursor BIGINT NOT NULL DEFAULT 0 CHECK (acknowledged_cursor >= 0),
    delivered_cursor BIGINT NOT NULL DEFAULT 0 CHECK (delivered_cursor >= acknowledged_cursor),
    created TEXT NOT NULL,
    PRIMARY KEY (account,name)
);
CREATE INDEX entries_author_id ON entries(author,id);
