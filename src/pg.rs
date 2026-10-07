//! PostgreSQL-only SQLx facade. Pin both internal crates in lockstep: their APIs
//! are semver-exempt. Avoids SQLx's unused SQLite driver's native-link conflict
//! and keeps the existing, newer rusqlite backend for local compatibility.
pub use sqlx_core::{
    connection::ConnectOptions, error::Error, query::query, query_scalar::query_scalar,
    raw_sql::raw_sql, row::Row, transaction::Transaction,
};
pub use sqlx_postgres::{self as postgres, PgPool, Postgres};
