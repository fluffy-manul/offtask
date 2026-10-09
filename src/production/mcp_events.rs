//! MCP 2026-07-28 webhook hints. These never acknowledge or drain an inbox.
//! Protocol cursors are null: the authenticated inbox is the replay surface.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::{aead, hmac};
use std::{
    collections::BTreeSet,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
};
use subtle::ConstantTimeEq;
use time::format_description::well_known::Rfc3339;

const EVENT: &str = "notification.available";
const DEFAULT_TTL: i64 = 3600;
const MAX_TTL: i64 = 86400;
const VERIFY_SECONDS: i64 = 300;
const ROTATION_SECONDS: i64 = 300;
const MAX_ATTEMPTS: i32 = 8;
const JOB_SECONDS: i64 = 3600;
const MAX_RESPONSE: usize = 8192;
const REQUEST_SECONDS: u64 = 5;

pub(super) struct Config {
    key: [u8; 32],
    hosts: BTreeSet<String>,
    transport: Arc<dyn CallbackTransport>,
}
impl Config {
    pub(super) fn from_env() -> Result<Option<Self>> {
        let key = env::var("OFFTASK_MCP_EVENTS_KEY").ok();
        let hosts = env::var("OFFTASK_MCP_CALLBACK_HOSTS").ok();
        if key.is_none() && hosts.is_none() {
            return Ok(None);
        }
        let key = STANDARD
            .decode(key.ok_or_else(|| err(400, "OFFTASK_MCP_EVENTS_KEY is required"))?)
            .map_err(|_| err(400, "OFFTASK_MCP_EVENTS_KEY must be base64 of 32 bytes"))?;
        let key: [u8; 32] = key
            .try_into()
            .map_err(|_| err(400, "OFFTASK_MCP_EVENTS_KEY must be base64 of 32 bytes"))?;
        let hosts =
            parse_hosts(&hosts.ok_or_else(|| err(400, "OFFTASK_MCP_CALLBACK_HOSTS is required"))?)?;
        Ok(Some(Self {
            key,
            hosts,
            transport: Arc::new(HttpsTransport),
        }))
    }
}
fn parse_hosts(value: &str) -> Result<BTreeSet<String>> {
    let hosts = value
        .split(',')
        .map(str::trim)
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if hosts.is_empty() || hosts.len() > 16 || hosts.iter().any(|h| !valid_host(h)) {
        return Err(err(
            400,
            "Callback allowlist requires exact lowercase DNS hosts, without wildcards or ports",
        ));
    }
    Ok(hosts)
}
fn valid_host(h: &str) -> bool {
    h.len() <= 253
        && h.contains('.')
        && !h.ends_with('.')
        && h.parse::<IpAddr>().is_err()
        && h.split('.').all(|s| {
            !s.is_empty()
                && s.len() <= 63
                && !s.starts_with('-')
                && !s.ends_with('-')
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}
fn callback_url(config: &Config, value: &str) -> Result<Url> {
    if value.len() > 4096
        || !value.is_ascii()
        || value.bytes().any(|b| b <= 32 || b == 127 || b == b'\\')
    {
        return Err(err(400, "Invalid callback URL"));
    }
    let url = Url::parse(value).map_err(|_| err(400, "Invalid callback URL"))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default() != Some(443)
        || !url
            .host_str()
            .is_some_and(|h| valid_host(h) && config.hosts.contains(h))
    {
        return Err(err(
            400,
            "Callback URL must use HTTPS port 443 and an exact allowed public host",
        ));
    }
    Ok(url)
}
// Conservative global-unicast test. Reject special-use, transition, documentation,
// multicast and reserved ranges, including mapped IPv4 and NAT64 IPv6 addresses.
fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let n = u32::from(a);
            ![
                (0x00000000u32, 8),
                (0x0a000000, 8),
                (0x64400000, 10),
                (0x7f000000, 8),
                (0xa9fe0000, 16),
                (0xac100000, 12),
                (0xc0000000, 24),
                (0xc0000200, 24),
                (0xc0586300, 24),
                (0xc0a80000, 16),
                (0xc6120000, 15),
                (0xc6336400, 24),
                (0xcb007100, 24),
                (0xe0000000, 4),
                (0xf0000000, 4),
            ]
            .iter()
            .any(|(base, bits)| n >> (32 - bits) == base >> (32 - bits))
        }
        IpAddr::V6(a) => {
            let n = u128::from(a);
            n >> 125 == 1
                && n >> 105 != 0x20010000000000000000000000000000u128 >> 105
                && n >> 96 != 0x20010db8000000000000000000000000u128 >> 96
                && n >> 112 != 0x2002
                && n >> 108 != 0x3fff0
        }
    }
}
fn checked_addresses(addresses: Vec<SocketAddr>) -> Result<Vec<SocketAddr>> {
    if addresses.is_empty()
        || addresses.len() > 32
        || addresses
            .iter()
            .any(|a| a.port() != 443 || !public_ip(a.ip()))
    {
        return Err(err(502, "callback_connection_refused"));
    }
    Ok(addresses)
}
struct CallbackRequest {
    url: Url,
    subscription_id: String,
    event_id: String,
    timestamp: i64,
    signature: String,
    body: String,
    verification: bool,
}
struct CallbackResponse {
    status: u16,
    body: Vec<u8>,
}
type CallbackFuture<'a> = Pin<Box<dyn Future<Output = Result<CallbackResponse>> + Send + 'a>>;
trait CallbackTransport: Send + Sync {
    fn post(&self, request: CallbackRequest) -> CallbackFuture<'_>;
}
struct HttpsTransport;
impl CallbackTransport for HttpsTransport {
    fn post(&self, request: CallbackRequest) -> CallbackFuture<'_> {
        Box::pin(async move {
            let operation = async {
                let host = request
                    .url
                    .host_str()
                    .ok_or_else(|| err(502, "callback_connection_refused"))?;
                let addresses = tokio::net::lookup_host((host, 443))
                    .await
                    .map_err(|_| err(502, "callback_connection_refused"))?
                    .collect::<Vec<_>>();
                let addresses = checked_addresses(addresses)?;
                // A new client for each request prevents pooled connections or stale DNS.
                // resolve_to_addrs pins the validated IPs, retaining URL hostname for TLS/SNI.
                let client = reqwest::Client::builder()
                    .https_only(true)
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .connect_timeout(Duration::from_secs(3))
                    .timeout(Duration::from_secs(REQUEST_SECONDS))
                    .pool_max_idle_per_host(0)
                    .resolve_to_addrs(host, &addresses)
                    .build()
                    .map_err(|_| err(502, "callback_connection_refused"))?;
                let mut response = client
                    .post(request.url)
                    .header("content-type", "application/json")
                    .header("webhook-id", request.event_id)
                    .header("webhook-timestamp", request.timestamp.to_string())
                    .header("webhook-signature", request.signature)
                    .header("X-MCP-Subscription-Id", request.subscription_id)
                    .body(request.body)
                    .send()
                    .await
                    .map_err(|e| {
                        err(
                            502,
                            if e.is_timeout() {
                                "callback_timeout"
                            } else {
                                "callback_connection_refused"
                            },
                        )
                    })?;
                let status = response.status().as_u16();
                // Application acknowledgments need only the status. In particular,
                // a 410/413 remains terminal regardless of its response body.
                if !request.verification || !(200..300).contains(&status) {
                    return Ok(CallbackResponse {
                        status,
                        body: Vec::new(),
                    });
                }
                if response
                    .content_length()
                    .is_some_and(|n| n > MAX_RESPONSE as u64)
                {
                    return Err(err(502, "callback_challenge_failed"));
                }
                let mut body = Vec::new();
                while let Some(chunk) = response
                    .chunk()
                    .await
                    .map_err(|_| err(502, "callback_connection_refused"))?
                {
                    if body.len() + chunk.len() > MAX_RESPONSE {
                        return Err(err(502, "callback_challenge_failed"));
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(CallbackResponse { status, body })
            };
            tokio::time::timeout(Duration::from_secs(REQUEST_SECONDS), operation)
                .await
                .map_err(|_| err(502, "callback_timeout"))?
        })
    }
}
fn decode_secret(value: &str) -> Result<Vec<u8>> {
    let raw = value
        .strip_prefix("whsec_")
        .filter(|s| s.len() <= 88)
        .ok_or_else(|| err(400, "Invalid webhook signing secret"))?;
    let key = STANDARD
        .decode(raw)
        .map_err(|_| err(400, "Invalid webhook signing secret"))?;
    if !(24..=64).contains(&key.len()) {
        return Err(err(400, "Invalid webhook signing secret"));
    }
    Ok(key)
}
fn signing_key(config: &Config) -> Result<aead::LessSafeKey> {
    aead::UnboundKey::new(&aead::AES_256_GCM, &config.key)
        .map(aead::LessSafeKey::new)
        .map_err(|_| err(503, "Webhook encryption unavailable"))
}
fn encrypt(config: &Config, id: &str, raw: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let mut cipher = raw.to_vec();
    signing_key(config)?
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(id.as_bytes()),
            &mut cipher,
        )
        .map_err(|_| err(503, "Webhook encryption unavailable"))?;
    let mut stored = nonce.to_vec();
    stored.extend(cipher);
    Ok(stored)
}
fn decrypt(config: &Config, id: &str, stored: &[u8]) -> Result<Vec<u8>> {
    if stored.len() < 12 + 16 {
        return Err(err(503, "Webhook key cannot be decrypted"));
    }
    let mut cipher = stored[12..].to_vec();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&stored[..12]);
    let key = signing_key(config)?;
    let raw = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(id.as_bytes()),
            &mut cipher,
        )
        .map_err(|_| err(503, "Webhook key cannot be decrypted"))?;
    Ok(raw.to_vec())
}
fn signature(raw: &[u8], id: &str, timestamp: i64, body: &str) -> String {
    let signed = format!("{id}.{timestamp}.{body}");
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, raw), signed.as_bytes());
    format!("v1,{}", STANDARD.encode(tag.as_ref()))
}
fn challenge_matches(response: &CallbackResponse, challenge: &str) -> bool {
    if !(200..300).contains(&response.status) || response.body.len() > MAX_RESPONSE {
        return false;
    }
    serde_json::from_slice::<Value>(&response.body)
        .ok()
        .and_then(|v| {
            v["challenge"]
                .as_str()
                .map(|s| s.as_bytes().ct_eq(challenge.as_bytes()).into())
        })
        .unwrap_or(false)
}
async fn verify(config: &Config, url: &Url, id: &str, raw: &[u8]) -> Result<()> {
    let challenge = secret("challenge_");
    let body = json!({"type":"verification","challenge":challenge}).to_string();
    let event_id = format!("msg_verification_{}", Uuid::new_v4());
    let timestamp = unix();
    let response = config
        .transport
        .post(CallbackRequest {
            url: url.clone(),
            subscription_id: id.into(),
            signature: signature(raw, &event_id, timestamp, &body),
            event_id,
            timestamp,
            body,
            verification: true,
        })
        .await?;
    if !challenge_matches(&response, &challenge) {
        return Err(err(
            502,
            if response.status >= 500 {
                "callback_http_5xx"
            } else if response.status >= 400 {
                "callback_http_4xx"
            } else {
                "callback_challenge_failed"
            },
        ));
    }
    Ok(())
}
pub(super) fn definition() -> Value {
    json!({"name":EVENT,"description":"A coalesced hint that this account-owned inbox has eligible unread entries. Read and explicitly acknowledge through the authenticated inbox tools. Hints contain no message content and do not support protocol replay.","delivery":["webhook"],
        "inputSchema":{"type":"object","properties":{"subscription":{"type":"string","pattern":"^[a-z0-9_-]{1,64}$"},"generation":{"type":"string","format":"uuid"}},"required":["subscription","generation"],"additionalProperties":false},
        "payloadSchema":{"type":"object","properties":{"subscription":{"type":"string"},"generation":{"type":"string"},"available":{"type":"boolean","const":true}},"required":["subscription","generation","available"],"additionalProperties":false}})
}
struct Identity {
    id: String,
    name: String,
    generation: String,
    url: Url,
}
fn identity(
    config: &Config,
    grant: &oauth::Grant,
    params: &Value,
    subscribe: bool,
) -> Result<Identity> {
    object_fields(
        params,
        if subscribe {
            &[
                "name",
                "arguments",
                "delivery",
                "cursor",
                "ttlMs",
                "maxAgeMs",
            ]
        } else {
            &["name", "arguments", "delivery"]
        },
    )?;
    if params["name"] != EVENT {
        return Err(err(404, "Event not found"));
    }
    object_fields(&params["arguments"], &["subscription", "generation"])?;
    let name = params["arguments"]["subscription"]
        .as_str()
        .filter(|s| {
            (1..=64).contains(&s.len())
                && s.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-')
                })
        })
        .ok_or_else(|| err(400, "Invalid inbox subscription"))?
        .to_owned();
    let generation = uuid(params["arguments"]["generation"].as_str().unwrap_or(""))?.to_owned();
    object_fields(
        &params["delivery"],
        if subscribe {
            &["mode", "url", "secret"]
        } else {
            &["mode", "url"]
        },
    )?;
    if params["delivery"]["mode"] != "webhook" {
        return Err(err(400, "Only webhook delivery is supported"));
    }
    let url = callback_url(config, params["delivery"]["url"].as_str().unwrap_or(""))?;
    // Fixed-order tuple is canonical regardless of incoming JSON property order.
    let canonical = json!([
        grant.id,
        grant.account,
        url.as_str(),
        EVENT,
        name,
        generation
    ])
    .to_string();
    Ok(Identity {
        id: format!("sub_{}", digest(&canonical)),
        name,
        generation,
        url,
    })
}
fn ttl_seconds(params: &Value) -> Result<i64> {
    if !params["cursor"].is_null() {
        return Err(err(
            400,
            "Notification hints do not support replay cursors; use the durable inbox",
        ));
    }
    if params.get("maxAgeMs").is_some_and(|v| !v.is_null()) {
        return Err(err(
            400,
            "Notification hints do not support replay maxAgeMs",
        ));
    }
    match params.get("ttlMs") {
        None | Some(Value::Null) => Ok(DEFAULT_TTL),
        Some(v) => v
            .as_u64()
            .filter(|n| *n > 0)
            .map(|ms| ((ms / 1000).max(60).min(MAX_TTL as u64)) as i64)
            .ok_or_else(|| err(400, "ttlMs must be null or a positive integer")),
    }
}
async fn inbox(
    tx: &mut Tx<'_>,
    grant: &oauth::Grant,
    identity: &Identity,
) -> Result<sqlx::postgres::PgRow> {
    sqlx::query(
        "SELECT * FROM notification_subscriptions WHERE account=$1 AND name=$2 AND generation=$3",
    )
    .bind(&grant.account)
    .bind(&identity.name)
    .bind(&identity.generation)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)?
    .ok_or_else(|| err(403, "Inbox subscription is unavailable for this grant"))
}
fn reconciliation() -> Error {
    err(
        409,
        "Subscription checkpoint is ahead of this database; operator reconciliation is required",
    )
}
async fn high_watermark(tx: &mut Tx<'_>) -> Result<i64> {
    sqlx::query_scalar("SELECT COALESCE(MAX(id),0) FROM events")
        .fetch_one(&mut **tx)
        .await
        .map_err(db_error)
}
pub(super) async fn subscribe(
    app: &Production,
    grant: &oauth::Grant,
    params: &Value,
) -> Result<Value> {
    let config = app
        .events
        .as_ref()
        .ok_or_else(|| err(503, "MCP events are disabled"))?;
    let identity = identity(config, grant, params, true)?;
    let ttl = ttl_seconds(params)?;
    let raw = decode_secret(params["delivery"]["secret"].as_str().unwrap_or(""))?;
    // Authorization and quotas are checked before any network activity.
    let mut tx = write_tx(&app.pool).await?;
    let current = oauth::grant_tx(app, &mut tx, &grant.id, "offtask:events").await?;
    if current.account != grant.account {
        return Err(err(403, "Grant account changed"));
    }
    let inbox_row = inbox(&mut tx, grant, &identity).await?;
    let high = high_watermark(&mut tx).await?;
    let ack: i64 = inbox_row.get("acknowledged_cursor");
    if ack > high || inbox_row.get::<i64, _>("delivered_cursor") > high {
        return Err(reconciliation());
    }
    let existing = sqlx::query("SELECT * FROM mcp_event_subscriptions WHERE id=$1 FOR UPDATE")
        .bind(&identity.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
    if existing
        .as_ref()
        .is_some_and(|r| r.get::<i64, _>("transport_cursor") > high)
    {
        return Err(reconciliation());
    }
    if existing.is_none() {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mcp_event_subscriptions WHERE account=$1 AND expires>$2",
        )
        .bind(&grant.account)
        .bind(unix())
        .fetch_one(&mut *tx)
        .await
        .map_err(db_error)?;
        if count >= 16 {
            return Err(err(429, "Webhook subscription limit reached"));
        }
    }
    let secret_hash = format!("{:x}", Sha256::digest(&raw));
    let cached: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mcp_callback_verifications WHERE grant_id=$1 AND callback_url=$2 AND secret_hash=$3 AND verified_until>$4)")
        .bind(&grant.id).bind(identity.url.as_str()).bind(&secret_hash).bind(unix()).fetch_one(&mut *tx).await.map_err(db_error)?;
    if !cached {
        let count:i32=sqlx::query_scalar("INSERT INTO rate_windows(actor,window_start,count) VALUES($1,$2,1) ON CONFLICT(actor) DO UPDATE SET window_start=$2,count=CASE WHEN rate_windows.window_start=$2 THEN rate_windows.count+1 ELSE 1 END RETURNING count")
            .bind(format!("mcp-verify:{}",grant.account)).bind(unix()/60).fetch_one(&mut *tx).await.map_err(db_error)?;
        if count > 6 {
            return Err(err(429, "Callback verification rate exceeded"));
        }
        // Commit the budget even when verification fails. The subscription is not active.
        tx.commit().await.map_err(db_error)?;
        verify(config, &identity.url, &identity.id, &raw).await?;
        tx = write_tx(&app.pool).await?;
        let rechecked = oauth::grant_tx(app, &mut tx, &grant.id, "offtask:events").await?;
        if rechecked.account != grant.account {
            return Err(err(403, "Grant account changed"));
        }
        inbox(&mut tx, grant, &identity).await?;
        sqlx::query("INSERT INTO mcp_callback_verifications(grant_id,callback_url,secret_hash,verified_until) VALUES($1,$2,$3,$4) ON CONFLICT(grant_id,callback_url) DO UPDATE SET secret_hash=$3,verified_until=$4")
            .bind(&grant.id).bind(identity.url.as_str()).bind(&secret_hash).bind(unix()+VERIFY_SECONDS).execute(&mut *tx).await.map_err(db_error)?;
    }
    // Re-read under the lock after verification: another subscription/refresh may have won.
    let inbox_row = inbox(&mut tx, grant, &identity).await?;
    let high = high_watermark(&mut tx).await?;
    let ack: i64 = inbox_row.get("acknowledged_cursor");
    if ack > high || inbox_row.get::<i64, _>("delivered_cursor") > high {
        return Err(reconciliation());
    }
    let existing = sqlx::query("SELECT * FROM mcp_event_subscriptions WHERE id=$1 FOR UPDATE")
        .bind(&identity.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
    let expires = unix() + ttl;
    let cipher = encrypt(config, &identity.id, &raw)?;
    if let Some(row) = existing {
        let cursor: i64 = row.get("transport_cursor");
        if cursor > high {
            return Err(reconciliation());
        }
        let old_cipher: Vec<u8> = row.get("secret_cipher");
        let old = decrypt(config, &identity.id, &old_cipher)?;
        let changed = !bool::from(old.ct_eq(&raw));
        let expired = row.get::<i64, _>("expires") <= unix() || row.get::<bool, _>("suspended");
        if expired {
            sqlx::query("DELETE FROM mcp_event_outbox WHERE subscription_id=$1")
                .bind(&identity.id)
                .execute(&mut *tx)
                .await
                .map_err(db_error)?;
        }
        sqlx::query("UPDATE mcp_event_subscriptions SET secret_cipher=$2,previous_secret_cipher=CASE WHEN $3 THEN $4 ELSE previous_secret_cipher END,previous_secret_until=CASE WHEN $3 THEN $5 ELSE previous_secret_until END,expires=$6,transport_cursor=$7,suspended=FALSE,last_error=NULL WHERE id=$1")
            .bind(&identity.id).bind(cipher).bind(changed).bind(old_cipher).bind(unix()+ROTATION_SECONDS).bind(expires).bind(if expired {ack} else {cursor}).execute(&mut *tx).await.map_err(db_error)?;
    } else {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mcp_event_subscriptions WHERE account=$1 AND expires>$2",
        )
        .bind(&grant.account)
        .bind(unix())
        .fetch_one(&mut *tx)
        .await
        .map_err(db_error)?;
        if count >= 16 {
            return Err(err(429, "Webhook subscription limit reached"));
        }
        sqlx::query("INSERT INTO mcp_event_subscriptions(id,grant_id,account,inbox_name,inbox_generation,callback_url,secret_cipher,expires,transport_cursor,created) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
            .bind(&identity.id).bind(&grant.id).bind(&grant.account).bind(&identity.name).bind(&identity.generation).bind(identity.url.as_str()).bind(cipher).bind(expires).bind(ack).bind(now()).execute(&mut *tx).await.map_err(db_error)?;
    }
    tx.commit().await.map_err(db_error)?;
    Ok(
        json!({"id":identity.id,"refreshBefore":OffsetDateTime::from_unix_timestamp(expires).map_err(|_| err(500,"Invalid expiration"))?.format(&Rfc3339).map_err(|_| err(500,"Invalid expiration"))?,"cursor":null,"truncated":false}),
    )
}
pub(super) async fn unsubscribe(
    app: &Production,
    grant: &oauth::Grant,
    params: &Value,
) -> Result<Value> {
    let config = app
        .events
        .as_ref()
        .ok_or_else(|| err(503, "MCP events are disabled"))?;
    let identity = identity(config, grant, params, false)?;
    let mut tx = write_tx(&app.pool).await?;
    let current = oauth::grant_tx(app, &mut tx, &grant.id, "offtask:events").await?;
    if current.account != grant.account {
        return Err(err(403, "Grant account changed"));
    }
    sqlx::query("DELETE FROM mcp_event_subscriptions WHERE id=$1 AND grant_id=$2 AND account=$3")
        .bind(identity.id)
        .bind(&grant.id)
        .bind(&grant.account)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;
    Ok(json!({}))
}
pub(super) async fn cancel_grant_tx(tx: &mut Tx<'_>, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM mcp_event_subscriptions WHERE grant_id=$1")
        .bind(id)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
    sqlx::query("DELETE FROM mcp_callback_verifications WHERE grant_id=$1")
        .bind(id)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
    Ok(())
}

async fn suspend(tx: &mut Tx<'_>, id: &str, reason: &str) -> Result<()> {
    sqlx::query("UPDATE mcp_event_subscriptions SET suspended=TRUE,last_error=$2 WHERE id=$1")
        .bind(id)
        .bind(reason)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
    sqlx::query("DELETE FROM mcp_event_outbox WHERE subscription_id=$1")
        .bind(id)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
    Ok(())
}
async fn enqueue(app: &Production) -> Result<()> {
    let mut tx = write_tx(&app.pool).await?;
    // Cleanup also prevents renewal from inheriting expired or revoked delivery work.
    sqlx::query("DELETE FROM mcp_event_subscriptions m USING oauth_grants g,accounts a WHERE m.grant_id=g.id AND m.account=a.id AND (m.expires<=$1 OR g.expires<=$1 OR g.revoked OR a.disabled)")
        .bind(unix()).execute(&mut *tx).await.map_err(db_error)?;
    sqlx::query("DELETE FROM mcp_callback_verifications WHERE verified_until<=$1")
        .bind(unix())
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    sqlx::query("UPDATE mcp_event_subscriptions SET previous_secret_cipher=NULL,previous_secret_until=0 WHERE previous_secret_cipher IS NOT NULL AND previous_secret_until<=$1")
        .bind(unix()).execute(&mut *tx).await.map_err(db_error)?;
    let high = high_watermark(&mut tx).await?;
    // A restored database must never silently advance a stale transport/inbox checkpoint.
    sqlx::query("UPDATE mcp_event_subscriptions m SET suspended=TRUE,last_error='checkpoint_ahead' FROM notification_subscriptions s WHERE m.inbox_generation=s.generation AND (m.transport_cursor>$1 OR s.acknowledged_cursor>$1 OR s.delivered_cursor>$1)")
        .bind(high).execute(&mut *tx).await.map_err(db_error)?;
    sqlx::query("DELETE FROM mcp_event_outbox o USING mcp_event_subscriptions m WHERE o.subscription_id=m.id AND m.suspended")
        .execute(&mut *tx).await.map_err(db_error)?;
    let query = format!(
        "SELECT m.*,candidate.cursor,candidate.event_created FROM mcp_event_subscriptions m JOIN notification_subscriptions s ON s.account=m.account AND s.name=m.inbox_name AND s.generation=m.inbox_generation CROSS JOIN LATERAL (SELECT ev.id AS cursor,ev.created AS event_created FROM events ev JOIN entries e ON e.id=ev.entry JOIN conversations c ON c.id=ev.conversation WHERE ev.id>GREATEST(m.transport_cursor,s.acknowledged_cursor) AND {} ORDER BY ev.id DESC LIMIT 1) candidate WHERE NOT m.suspended AND m.expires>$1 AND NOT EXISTS(SELECT 1 FROM mcp_event_outbox o WHERE o.subscription_id=m.id) ORDER BY m.id LIMIT 64",
        notifications::ELIGIBLE
    );
    let rows = sqlx::query(&query)
        .bind(unix())
        .fetch_all(&mut *tx)
        .await
        .map_err(db_error)?;
    for row in rows {
        let id: String = row.get("id");
        let grant_id: String = row.get("grant_id");
        let account: String = row.get("account");
        match oauth::grant_tx(app, &mut tx, &grant_id, "offtask:events").await {
            Ok(g) if g.account == account => {}
            Ok(_) => {
                cancel_grant_tx(&mut tx, &grant_id).await?;
                continue;
            }
            Err(e) if matches!(e.0, 401 | 403) => {
                cancel_grant_tx(&mut tx, &grant_id).await?;
                continue;
            }
            Err(e) => return Err(e),
        }
        let event_id = format!("evt_{}", Uuid::new_v4());
        let cursor: i64 = row.get("cursor");
        let body=json!({"eventId":event_id,"name":EVENT,"timestamp":row.get::<String,_>("event_created"),
            "data":{"subscription":row.get::<String,_>("inbox_name"),"generation":row.get::<String,_>("inbox_generation"),"available":true},"cursor":null}).to_string();
        sqlx::query("INSERT INTO mcp_event_outbox(subscription_id,event_id,transport_cursor,body,next_attempt,expires,created) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(subscription_id) DO NOTHING")
            .bind(id).bind(event_id).bind(cursor).bind(body).bind(unix()).bind((unix()+JOB_SECONDS).min(row.get::<i64,_>("expires"))).bind(now())
            .execute(&mut *tx).await.map_err(db_error)?;
    }
    tx.commit().await.map_err(db_error)
}
fn retry_delay(attempts: i32) -> i64 {
    (5i64 << attempts.clamp(0, 7)).min(600)
}
fn retryable_status(status: u16) -> bool {
    status == 408 || status == 429 || status >= 500
}
async fn pending_eligible(tx: &mut Tx<'_>, row: &sqlx::postgres::PgRow) -> Result<bool> {
    let query = format!(
        "SELECT EXISTS(SELECT 1 FROM notification_subscriptions s JOIN events ev ON ev.id>GREATEST(s.acknowledged_cursor,$4) JOIN entries e ON e.id=ev.entry JOIN conversations c ON c.id=ev.conversation WHERE s.account=$1 AND s.name=$2 AND s.generation=$3 AND ev.id<=$5 AND {})",
        notifications::ELIGIBLE
    );
    sqlx::query_scalar(&query)
        .bind(row.get::<String, _>("account"))
        .bind(row.get::<String, _>("inbox_name"))
        .bind(row.get::<String, _>("inbox_generation"))
        .bind(row.get::<i64, _>("transport_cursor"))
        .bind(row.get::<i64, _>("pending_cursor"))
        .fetch_one(&mut **tx)
        .await
        .map_err(db_error)
}
async fn finish_hint(tx: &mut Tx<'_>, id: &str, cursor: i64) -> Result<()> {
    sqlx::query("UPDATE mcp_event_subscriptions SET transport_cursor=GREATEST(transport_cursor,$2),last_error=NULL WHERE id=$1")
        .bind(id).bind(cursor).execute(&mut **tx).await.map_err(db_error)?;
    sqlx::query("DELETE FROM mcp_event_outbox WHERE subscription_id=$1")
        .bind(id)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
    Ok(())
}
/// The outbox is committed before attempting delivery. A durable, fenced lease
/// claims a job after a current ACL check; no database transaction or writer lock
/// is held across outbound I/O. An already in-flight callback cannot be recalled,
/// but unsubscribe/revocation deletes pending work and prevents new claims. A
/// process failure leaves the same event ID/body available after lease expiry.
pub(super) async fn run_once(app: &Production) -> Result<bool> {
    let Some(config) = app.events.as_ref() else {
        return Ok(false);
    };
    enqueue(app).await?;
    let mut tx = write_tx(&app.pool).await?;
    let row=sqlx::query("SELECT m.*,o.event_id,o.transport_cursor AS pending_cursor,o.body,o.attempts,o.expires AS job_expires FROM mcp_event_outbox o JOIN mcp_event_subscriptions m ON m.id=o.subscription_id WHERE o.next_attempt<=$1 AND o.lease_until<=$1 ORDER BY o.next_attempt,o.subscription_id LIMIT 1 FOR UPDATE OF o,m SKIP LOCKED")
        .bind(unix()).fetch_optional(&mut *tx).await.map_err(db_error)?;
    let Some(row) = row else {
        tx.commit().await.map_err(db_error)?;
        return Ok(false);
    };
    let id: String = row.get("id");
    let grant_id: String = row.get("grant_id");
    let valid = match oauth::grant_tx(app, &mut tx, &grant_id, "offtask:events").await {
        Ok(g) => g.account == row.get::<String, _>("account"),
        Err(e) if matches!(e.0, 401 | 403) => false,
        Err(e) => return Err(e),
    };
    if !valid || row.get::<i64, _>("expires") <= unix() {
        sqlx::query("DELETE FROM mcp_event_subscriptions WHERE id=$1")
            .bind(&id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        tx.commit().await.map_err(db_error)?;
        return Ok(true);
    }
    if row.get::<bool, _>("suspended")
        || row.get::<i64, _>("job_expires") <= unix()
        || row.get::<i32, _>("attempts") >= MAX_ATTEMPTS
    {
        suspend(&mut tx, &id, "delivery_expired").await?;
        tx.commit().await.map_err(db_error)?;
        return Ok(true);
    }
    let high = high_watermark(&mut tx).await?;
    let pending: i64 = row.get("pending_cursor");
    if pending > high || row.get::<i64, _>("transport_cursor") > high {
        suspend(&mut tx, &id, "checkpoint_ahead").await?;
        tx.commit().await.map_err(db_error)?;
        return Ok(true);
    }
    // Recheck the exact pending range, not merely the latest entry, after ACK,
    // blocks, redaction, membership changes, grant revocation and generation changes.
    if !pending_eligible(&mut tx, &row).await? {
        finish_hint(&mut tx, &id, pending).await?;
        tx.commit().await.map_err(db_error)?;
        return Ok(true);
    }
    let url = match callback_url(config, &row.get::<String, _>("callback_url")) {
        Ok(url) => url,
        Err(_) => {
            suspend(&mut tx, &id, "callback_not_allowed").await?;
            tx.commit().await.map_err(db_error)?;
            return Ok(true);
        }
    };
    let current = match decrypt(config, &id, &row.get::<Vec<u8>, _>("secret_cipher")) {
        Ok(secret) => secret,
        Err(_) => {
            suspend(&mut tx, &id, "secret_unavailable").await?;
            tx.commit().await.map_err(db_error)?;
            return Ok(true);
        }
    };
    let event_id: String = row.get("event_id");
    let body: String = row.get("body");
    let timestamp = unix();
    let mut signed = signature(&current, &event_id, timestamp, &body);
    if row.get::<i64, _>("previous_secret_until") > timestamp
        && let Some(cipher) = row.get::<Option<Vec<u8>>, _>("previous_secret_cipher")
    {
        let previous = match decrypt(config, &id, &cipher) {
            Ok(secret) => secret,
            Err(_) => {
                suspend(&mut tx, &id, "secret_unavailable").await?;
                tx.commit().await.map_err(db_error)?;
                return Ok(true);
            }
        };
        signed.push(' ');
        signed.push_str(&signature(&previous, &event_id, timestamp, &body));
    }
    let lease = Uuid::new_v4().to_string();
    sqlx::query("UPDATE mcp_event_outbox SET lease_id=$2,lease_until=$3,attempts=attempts+1 WHERE subscription_id=$1")
        .bind(&id)
        .bind(&lease)
        .bind(unix() + 30)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;
    let response = config
        .transport
        .post(CallbackRequest {
            url,
            subscription_id: id.clone(),
            event_id,
            timestamp,
            signature: signed,
            body,
            verification: false,
        })
        .await;
    let mut tx = write_tx(&app.pool).await?;
    let owned:bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mcp_event_outbox o JOIN mcp_event_subscriptions m ON m.id=o.subscription_id WHERE o.subscription_id=$1 AND o.lease_id=$2 AND NOT m.suspended AND m.expires>$3)")
        .bind(&id).bind(&lease).bind(unix()).fetch_one(&mut *tx).await.map_err(db_error)?;
    if !owned {
        tx.commit().await.map_err(db_error)?;
        return Ok(true);
    }
    let still_valid = match oauth::grant_tx(app, &mut tx, &grant_id, "offtask:events").await {
        Ok(g) => g.account == row.get::<String, _>("account"),
        Err(e) if matches!(e.0, 401 | 403) => false,
        Err(e) => return Err(e),
    };
    if !still_valid {
        cancel_grant_tx(&mut tx, &grant_id).await?;
        tx.commit().await.map_err(db_error)?;
        return Ok(true);
    }
    match response {
        Ok(r) if (200..300).contains(&r.status) => finish_hint(&mut tx, &id, pending).await?,
        Ok(r) if !retryable_status(r.status) => {
            suspend(
                &mut tx,
                &id,
                if r.status == 410 {
                    "callback_gone"
                } else if r.status == 413 {
                    "payload_rejected"
                } else {
                    "callback_rejected"
                },
            )
            .await?
        }
        response => {
            let attempts = row.get::<i32, _>("attempts") + 1;
            if attempts >= MAX_ATTEMPTS {
                suspend(&mut tx, &id, "attempts_exhausted").await?;
            } else {
                let reason = match response {
                    Ok(r) if r.status >= 500 => "http_5xx",
                    Ok(_) => "retry_later",
                    Err(e) if e.1 == "callback_timeout" => "timeout",
                    _ => "transport_error",
                };
                sqlx::query("UPDATE mcp_event_outbox SET attempts=$2,next_attempt=$3,lease_id=NULL,lease_until=0 WHERE subscription_id=$1")
                    .bind(&id).bind(attempts).bind(unix()+retry_delay(attempts)).execute(&mut *tx).await.map_err(db_error)?;
                sqlx::query("UPDATE mcp_event_subscriptions SET last_error=$2 WHERE id=$1")
                    .bind(&id)
                    .bind(reason)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_error)?;
            }
        }
    }
    tx.commit().await.map_err(db_error)?;
    Ok(true)
}
pub(super) async fn worker_loop(app: Production) {
    if app.events.is_none() {
        return;
    }
    loop {
        let delay = match run_once(&app).await {
            Ok(true) => Duration::from_millis(100),
            Ok(false) => Duration::from_secs(2),
            Err(_) => {
                eprintln!("MCP event worker paused; delivery state retained");
                Duration::from_secs(10)
            }
        };
        tokio::time::sleep(delay).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Default)]
    struct FakeTransport {
        requests: Mutex<Vec<CallbackRequest>>,
        statuses: Mutex<VecDeque<u16>>,
        wrong_challenge: bool,
        pause: Mutex<Option<Arc<Pause>>>,
    }
    struct Pause {
        entered: tokio::sync::Notify,
        resume: tokio::sync::Notify,
    }
    impl CallbackTransport for FakeTransport {
        fn post(&self, request: CallbackRequest) -> CallbackFuture<'_> {
            Box::pin(async move {
                let value: Value = serde_json::from_str(&request.body).unwrap();
                let (status, body) = if value["type"] == "verification" {
                    (
                        200,
                        if self.wrong_challenge {
                            json!({"challenge":"wrong"})
                        } else {
                            json!({"challenge":value["challenge"]})
                        }
                        .to_string()
                        .into_bytes(),
                    )
                } else {
                    (
                        self.statuses.lock().unwrap().pop_front().unwrap_or(204),
                        vec![],
                    )
                };
                let pause = if request.verification {
                    None
                } else {
                    self.pause.lock().unwrap().take()
                };
                self.requests.lock().unwrap().push(request);
                if let Some(pause) = pause {
                    pause.entered.notify_one();
                    pause.resume.notified().await;
                }
                Ok(CallbackResponse { status, body })
            })
        }
    }
    fn config(fake: Arc<FakeTransport>) -> Config {
        Config {
            key: [7; 32],
            hosts: parse_hosts("receiver.example.com").unwrap(),
            transport: fake,
        }
    }
    fn sample_grant() -> oauth::Grant {
        oauth::Grant {
            id: Uuid::new_v4().to_string(),
            account: Uuid::new_v4().to_string(),
        }
    }
    fn params(generation: &str) -> Value {
        json!({"name":EVENT,"arguments":{"subscription":"inbox","generation":generation},"delivery":{"mode":"webhook","url":"https://receiver.example.com/callback","secret":format!("whsec_{}",STANDARD.encode([9u8;32]))},"cursor":null})
    }
    fn unsub(p: &Value) -> Value {
        let mut p = p.clone();
        p.as_object_mut().unwrap().remove("cursor");
        p.as_object_mut().unwrap().remove("ttlMs");
        p["delivery"].as_object_mut().unwrap().remove("secret");
        p
    }
    #[test]
    fn standard_webhooks_vector_and_ciphertext_binding() {
        let raw: Vec<u8> = (0..32).collect();
        let body = "{\"eventId\":\"evt_test\",\"name\":\"notification.available\",\"cursor\":null}";
        assert_eq!(
            signature(&raw, "evt_test", 1700000000, body),
            "v1,PmC4Pq/xLh5fh5f/oXtzFAYF44UFCHf3U1NpNtTvlRE="
        );
        assert_ne!(
            signature(&raw, "evt_test", 1700000000, body),
            signature(&raw, "evt_test", 1700000001, body)
        );
        for n in [24, 32, 64] {
            assert_eq!(
                decode_secret(&format!("whsec_{}", STANDARD.encode(vec![8; n])))
                    .unwrap()
                    .len(),
                n
            );
        }
        for n in [0, 23, 65] {
            assert!(decode_secret(&format!("whsec_{}", STANDARD.encode(vec![8; n]))).is_err());
        }
        assert!(decode_secret("invalid").is_err());
        let cfg = config(Arc::new(FakeTransport::default()));
        let cipher = encrypt(&cfg, "sub_a", &raw).unwrap();
        assert_ne!(cipher, raw);
        assert_eq!(decrypt(&cfg, "sub_a", &cipher).unwrap(), raw);
        assert!(decrypt(&cfg, "sub_b", &cipher).is_err());
        let mut changed = cipher.clone();
        changed[14] ^= 1;
        assert!(decrypt(&cfg, "sub_a", &changed).is_err());
        assert_ne!(encrypt(&cfg, "sub_a", &raw).unwrap(), cipher);
    }
    #[tokio::test]
    async fn signed_single_use_challenge_and_failure() {
        let fake = Arc::new(FakeTransport::default());
        let cfg = config(fake.clone());
        let url = callback_url(&cfg, "https://receiver.example.com/callback").unwrap();
        verify(&cfg, &url, "sub_test", &[9; 32]).await.unwrap();
        verify(&cfg, &url, "sub_test", &[9; 32]).await.unwrap();
        {
            let requests = fake.requests.lock().unwrap();
            assert_eq!(requests.len(), 2);
            assert_ne!(requests[0].body, requests[1].body);
            assert_ne!(requests[0].event_id, requests[1].event_id);
            for r in requests.iter() {
                assert_eq!(
                    r.signature,
                    signature(&[9; 32], &r.event_id, r.timestamp, &r.body)
                );
                assert_eq!(r.subscription_id, "sub_test");
            }
        }
        let bad = config(Arc::new(FakeTransport {
            wrong_challenge: true,
            ..Default::default()
        }));
        assert_eq!(
            verify(&bad, &url, "sub_test", &[9; 32])
                .await
                .unwrap_err()
                .1,
            "callback_challenge_failed"
        );
        assert!(!challenge_matches(
            &CallbackResponse {
                status: 302,
                body: br#"{"challenge":"same"}"#.to_vec()
            },
            "same"
        ));
        assert!(!challenge_matches(
            &CallbackResponse {
                status: 200,
                body: br#"{"challenge":"same"}"#.to_vec()
            },
            "different"
        ));
    }
    #[test]
    fn ssrf_urls_and_dns_addresses_fail_closed() {
        let cfg = config(Arc::new(FakeTransport::default()));
        for url in [
            "http://receiver.example.com/callback",
            "https://receiver.example.com:444/callback",
            "https://receiver.example.com.evil.test/",
            "https://evil.receiver.example.com/",
            "https://receiver.example.com./",
            "https://receiver.example.com@127.0.0.1/",
            "https://user:pass@receiver.example.com/",
            "https://receiver.example.com/#fragment",
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://receiver.example.com\\@evil.test/",
            "https://receiver.example.com/\n",
        ] {
            assert!(callback_url(&cfg, url).is_err(), "{url}");
        }
        assert!(
            callback_url(
                &cfg,
                "https://receiver.example.com/callback?token=synthetic"
            )
            .is_ok()
        );
        for h in [
            "*",
            "*.example.com",
            "https://example.com",
            "127.0.0.1",
            "example.com:443",
            "example.com.",
            "EXAMPLE.com",
            "localhost",
            "",
        ] {
            assert!(parse_hosts(h).is_err(), "{h}");
        }
        for ip in [
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.0.0.1",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "2001::1",
            "2002:808:808::1",
            "3fff::1",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(public_ip(ip.parse().unwrap()), "{ip}");
        }
        assert!(checked_addresses(vec![]).is_err());
        assert!(
            checked_addresses(vec![
                "8.8.8.8:443".parse().unwrap(),
                "127.0.0.1:443".parse().unwrap()
            ])
            .is_err()
        );
        assert!(checked_addresses(vec!["8.8.8.8:80".parse().unwrap()]).is_err());
    }
    #[test]
    fn canonical_identity_and_ttl_do_not_accept_owner_or_replay() {
        let cfg = config(Arc::new(FakeTransport::default()));
        let g = sample_grant();
        let generation = Uuid::new_v4().to_string();
        let p = params(&generation);
        let id = identity(&cfg, &g, &p, true).unwrap().id;
        let mut reordered = p.clone();
        reordered["arguments"] = json!({"generation":generation,"subscription":"inbox"});
        assert_eq!(id, identity(&cfg, &g, &reordered, true).unwrap().id);
        assert_ne!(id, identity(&cfg, &sample_grant(), &p, true).unwrap().id);
        reordered["arguments"]["account"] = json!(g.account);
        assert!(identity(&cfg, &g, &reordered, true).is_err());
        assert_eq!(ttl_seconds(&p).unwrap(), DEFAULT_TTL);
        for (ttl, seconds) in [(1, 60), (60000, 60), (999999999, MAX_TTL)] {
            let mut p = p.clone();
            p["ttlMs"] = json!(ttl);
            assert_eq!(ttl_seconds(&p).unwrap(), seconds);
        }
        let mut p = p;
        p["cursor"] = json!("10");
        assert!(ttl_seconds(&p).is_err());
        assert!(!retryable_status(410));
        assert!(!retryable_status(413));
        assert!(!retryable_status(302));
        assert!(retryable_status(429));
        assert!(retryable_status(503));
        assert!(retry_delay(8) <= 600);
    }

    struct Fixture {
        app: Production,
        fake: Arc<FakeTransport>,
        grant: oauth::Grant,
        other: oauth::Grant,
        sender: String,
        generation: String,
        other_generation: String,
    }
    async fn fixture() -> Fixture {
        let url = env::var("TEST_DATABASE_URL")
            .expect("Explicit PostgreSQL tests require disposable TEST_DATABASE_URL");
        let options = PgConnectOptions::from_str(&url)
            .unwrap()
            .disable_statement_logging();
        let base = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(options.clone())
            .await
            .unwrap();
        let schema = format!("mcp_events_test_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&base)
            .await
            .unwrap();
        base.close().await;
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect_with(options.options([("search_path", schema.as_str())]))
            .await
            .unwrap();
        let mut app = Production::new(pool, "https://offtask.example")
            .await
            .unwrap();
        app.oauth = Some(Arc::new(
            oauth::Config::new(
                &app.origin,
                "synthetic-client",
                vec!["https://receiver.example.com/oauth".into()],
            )
            .unwrap(),
        ));
        let fake = Arc::new(FakeTransport::default());
        app.events = Some(Arc::new(config(fake.clone())));
        let grant = sample_grant();
        let other = sample_grant();
        let sender = Uuid::new_v4().to_string();
        for id in [&grant.account, &other.account, &sender] {
            sqlx::query("INSERT INTO accounts(id,name,bio,declared_dot,declaration_version,created) VALUES($1,'Synthetic','Test only',TRUE,1,$2)")
                .bind(id).bind(now()).execute(&app.pool).await.unwrap();
        }
        for g in [&grant, &other] {
            sqlx::query("INSERT INTO oauth_grants(id,account,issuer,resource,client_id,redirect_uri,scopes,expires,created) VALUES($1,$2,'https://offtask.example','https://offtask.example/mcp','synthetic-client','https://receiver.example.com/oauth',$3,$4,$5)")
                .bind(&g.id).bind(&g.account).bind(vec!["offtask:events".to_string(),"offtask:read".to_string(),"offtask:ack".to_string()]).bind(unix()+86400).bind(now()).execute(&app.pool).await.unwrap();
        }
        let generation = Uuid::new_v4().to_string();
        let other_generation = Uuid::new_v4().to_string();
        for (g, generation) in [(&grant, &generation), (&other, &other_generation)] {
            sqlx::query("INSERT INTO notification_subscriptions(account,generation,name,senders,visibility,created) VALUES($1,$2,'inbox',$3,'all',$4)")
                .bind(&g.account).bind(generation).bind(vec![sender.clone()]).bind(now()).execute(&app.pool).await.unwrap();
        }
        Fixture {
            app,
            fake,
            grant,
            other,
            sender,
            generation,
            other_generation,
        }
    }
    async fn event(f: &Fixture, private: bool) -> i64 {
        let c = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO conversations(id,visibility,title,creator,created) VALUES($1,$2,'Synthetic',$3,$4)")
            .bind(&c).bind(if private {"private"} else {"public"}).bind(&f.sender).bind(now()).execute(&f.app.pool).await.unwrap();
        let entry:i64=sqlx::query_scalar("INSERT INTO entries(conversation,author,body,created) VALUES($1,$2,'SENSITIVE SYNTHETIC CONTENT NEVER IN CALLBACK',$3) RETURNING id")
            .bind(&c).bind(&f.sender).bind(now()).fetch_one(&f.app.pool).await.unwrap();
        sqlx::query_scalar("INSERT INTO events(conversation,entry,kind,created) VALUES($1,$2,'entry.created',$3) RETURNING id")
            .bind(&c).bind(entry).bind(now()).fetch_one(&f.app.pool).await.unwrap()
    }
    async fn count(f: &Fixture, table: &str) -> i64 {
        sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&f.app.pool)
            .await
            .unwrap()
    }
    async fn due(f: &Fixture) {
        sqlx::query("UPDATE mcp_event_outbox SET next_attempt=0")
            .execute(&f.app.pool)
            .await
            .unwrap();
    }
    fn application_requests(f: &Fixture) -> Vec<(String, String, String)> {
        f.fake
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| serde_json::from_str::<Value>(&r.body).unwrap()["type"] != "verification")
            .map(|r| (r.event_id.clone(), r.body.clone(), r.signature.clone()))
            .collect()
    }
    #[tokio::test]
    #[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
    async fn persisted_retry_refresh_and_inbox_ack_are_independent() {
        let f = fixture().await;
        let p = params(&f.generation);
        // Another box cannot borrow this inbox generation, even using the same name.
        assert_eq!(subscribe(&f.app, &f.other, &p).await.unwrap_err().0, 403);
        assert!(f.fake.requests.lock().unwrap().is_empty());
        let subscription = subscribe(&f.app, &f.grant, &p).await.unwrap();
        let mut reversed = p.clone();
        reversed["arguments"] = json!({"generation":f.generation,"subscription":"inbox"});
        assert_eq!(
            subscribe(&f.app, &f.grant, &reversed).await.unwrap()["id"],
            subscription["id"]
        );
        assert_eq!(
            f.fake.requests.lock().unwrap().len(),
            1,
            "verification cached across refresh"
        );
        assert_eq!(count(&f, "mcp_event_subscriptions").await, 1);
        let secret_row = sqlx::query("SELECT secret_cipher FROM mcp_event_subscriptions")
            .fetch_one(&f.app.pool)
            .await
            .unwrap();
        let cipher: Vec<u8> = secret_row.get("secret_cipher");
        assert!(!cipher.windows(32).any(|w| w == [9; 32]));
        let first = event(&f, false).await;
        let second = event(&f, false).await;
        event(&f, true).await;
        f.fake.statuses.lock().unwrap().push_back(503);
        assert!(run_once(&f.app).await.unwrap());
        let pending = sqlx::query("SELECT * FROM mcp_event_outbox")
            .fetch_one(&f.app.pool)
            .await
            .unwrap();
        assert_eq!(pending.get::<i64, _>("transport_cursor"), second);
        assert_eq!(pending.get::<i32, _>("attempts"), 1);
        let stable_id: String = pending.get("event_id");
        let stable_body: String = pending.get("body");
        assert!(!stable_body.contains("SENSITIVE"));
        assert!(!stable_body.contains(&f.sender));
        assert!(serde_json::from_str::<Value>(&stable_body).unwrap()["cursor"].is_null());
        let inbox = sqlx::query("SELECT * FROM notification_subscriptions WHERE account=$1")
            .bind(&f.grant.account)
            .fetch_one(&f.app.pool)
            .await
            .unwrap();
        assert_eq!(inbox.get::<i64, _>("acknowledged_cursor"), 0);
        assert_eq!(inbox.get::<i64, _>("delivered_cursor"), 0);
        // Refresh rotates the secret but retains the exact pending occurrence.
        let mut rotated = p.clone();
        rotated["delivery"]["secret"] = json!(format!("whsec_{}", STANDARD.encode([10; 32])));
        assert_eq!(
            subscribe(&f.app, &f.grant, &rotated).await.unwrap()["id"],
            subscription["id"]
        );
        let pending_after = sqlx::query("SELECT event_id,body FROM mcp_event_outbox")
            .fetch_one(&f.app.pool)
            .await
            .unwrap();
        assert_eq!(pending_after.get::<String, _>("event_id"), stable_id);
        assert_eq!(pending_after.get::<String, _>("body"), stable_body);
        // New process-local state over the same durable DB resumes the same outbox.
        let mut restarted = Production::new(f.app.pool.clone(), "https://offtask.example")
            .await
            .unwrap();
        restarted.oauth = f.app.oauth.clone();
        restarted.events = Some(Arc::new(config(f.fake.clone())));
        due(&f).await;
        assert!(run_once(&restarted).await.unwrap());
        let sent = application_requests(&f);
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].0, sent[1].0);
        assert_eq!(sent[0].1, sent[1].1);
        assert_eq!(
            sent[1].2.split(' ').count(),
            2,
            "rotation overlap sends both signatures"
        );
        assert_eq!(count(&f, "mcp_event_outbox").await, 0);
        let checkpoint: i64 =
            sqlx::query_scalar("SELECT transport_cursor FROM mcp_event_subscriptions")
                .fetch_one(&f.app.pool)
                .await
                .unwrap();
        assert_eq!(checkpoint, second);
        let ack: i64 = sqlx::query_scalar(
            "SELECT acknowledged_cursor FROM notification_subscriptions WHERE account=$1",
        )
        .bind(&f.grant.account)
        .fetch_one(&f.app.pool)
        .await
        .unwrap();
        assert_eq!(ack, 0);
        assert!(
            !run_once(&f.app).await.unwrap(),
            "private inaccessible event produces no hint"
        );
        assert!(first < second);
        // Transport idempotency cannot grant another box permission to unsubscribe.
        unsubscribe(&f.app, &f.other, &unsub(&p)).await.unwrap();
        assert_eq!(count(&f, "mcp_event_subscriptions").await, 1);
        unsubscribe(&f.app, &f.grant, &unsub(&p)).await.unwrap();
        unsubscribe(&f.app, &f.grant, &unsub(&p)).await.unwrap();
        assert_eq!(count(&f, "mcp_event_subscriptions").await, 0);
        assert!(!run_once(&f.app).await.unwrap());
    }
    #[tokio::test]
    #[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
    async fn access_changes_expiry_and_generation_stop_queued_delivery() {
        let f = fixture().await;
        let p = params(&f.generation);
        subscribe(&f.app, &f.grant, &p).await.unwrap();
        let e = event(&f, false).await;
        enqueue(&f.app).await.unwrap();
        assert_eq!(count(&f, "mcp_event_outbox").await, 1);
        // A real durable ACK, unlike webhook receipt, removes eligibility.
        sqlx::query("UPDATE notification_subscriptions SET delivered_cursor=$2,acknowledged_cursor=$2 WHERE account=$1")
            .bind(&f.grant.account).bind(e).execute(&f.app.pool).await.unwrap();
        run_once(&f.app).await.unwrap();
        assert!(application_requests(&f).is_empty());
        event(&f, false).await;
        enqueue(&f.app).await.unwrap();
        sqlx::query("INSERT INTO blocks(blocker,blocked) VALUES($1,$2)")
            .bind(&f.grant.account)
            .bind(&f.sender)
            .execute(&f.app.pool)
            .await
            .unwrap();
        run_once(&f.app).await.unwrap();
        assert!(application_requests(&f).is_empty());
        sqlx::query("DELETE FROM blocks")
            .execute(&f.app.pool)
            .await
            .unwrap();
        event(&f, false).await;
        enqueue(&f.app).await.unwrap();
        sqlx::query("UPDATE accounts SET disabled=TRUE WHERE id=$1")
            .bind(&f.grant.account)
            .execute(&f.app.pool)
            .await
            .unwrap();
        run_once(&f.app).await.unwrap();
        assert!(application_requests(&f).is_empty());
        assert_eq!(count(&f, "mcp_event_subscriptions").await, 0);
        sqlx::query("UPDATE accounts SET disabled=FALSE WHERE id=$1")
            .bind(&f.grant.account)
            .execute(&f.app.pool)
            .await
            .unwrap();
        subscribe(&f.app, &f.grant, &p).await.unwrap();
        enqueue(&f.app).await.unwrap();
        sqlx::query("UPDATE oauth_grants SET revoked=TRUE WHERE id=$1")
            .bind(&f.grant.id)
            .execute(&f.app.pool)
            .await
            .unwrap();
        run_once(&f.app).await.unwrap();
        assert!(application_requests(&f).is_empty());
        assert_eq!(count(&f, "mcp_event_outbox").await, 0);
        sqlx::query("UPDATE oauth_grants SET revoked=FALSE WHERE id=$1")
            .bind(&f.grant.id)
            .execute(&f.app.pool)
            .await
            .unwrap();
        subscribe(&f.app, &f.grant, &p).await.unwrap();
        enqueue(&f.app).await.unwrap();
        sqlx::query("UPDATE mcp_event_subscriptions SET expires=0")
            .execute(&f.app.pool)
            .await
            .unwrap();
        run_once(&f.app).await.unwrap();
        assert!(application_requests(&f).is_empty());
        assert_eq!(count(&f, "mcp_event_subscriptions").await, 0);
        // Expired refresh creates a new catch-up hint for the still unread durable inbox.
        subscribe(&f.app, &f.grant, &p).await.unwrap();
        enqueue(&f.app).await.unwrap();
        assert_eq!(count(&f, "mcp_event_outbox").await, 1);
        sqlx::query("DELETE FROM notification_subscriptions WHERE account=$1")
            .bind(&f.grant.account)
            .execute(&f.app.pool)
            .await
            .unwrap();
        assert_eq!(count(&f, "mcp_event_outbox").await, 0);
        assert_eq!(count(&f, "mcp_event_subscriptions").await, 0);
        assert_eq!(subscribe(&f.app, &f.grant, &p).await.unwrap_err().0, 403);
        // The same human-readable inbox name in another box is still independent.
        assert!(
            subscribe(&f.app, &f.other, &params(&f.other_generation))
                .await
                .is_ok()
        );
    }
    #[tokio::test]
    #[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
    async fn lease_recovery_permanent_failures_and_reset_are_safe() {
        let f = fixture().await;
        let p = params(&f.generation);
        let result = subscribe(&f.app, &f.grant, &p).await.unwrap();
        event(&f, false).await;
        enqueue(&f.app).await.unwrap();
        let id: String = sqlx::query_scalar("SELECT event_id FROM mcp_event_outbox")
            .fetch_one(&f.app.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE mcp_event_outbox SET lease_id='crashed-worker',lease_until=$1")
            .bind(unix() + 30)
            .execute(&f.app.pool)
            .await
            .unwrap();
        assert!(!run_once(&f.app).await.unwrap());
        assert!(application_requests(&f).is_empty());
        sqlx::query("UPDATE mcp_event_outbox SET lease_until=0")
            .execute(&f.app.pool)
            .await
            .unwrap();
        f.fake.statuses.lock().unwrap().push_back(410);
        assert!(run_once(&f.app).await.unwrap());
        assert_eq!(application_requests(&f)[0].0, id);
        assert_eq!(count(&f, "mcp_event_outbox").await, 0);
        let suspended: bool = sqlx::query_scalar("SELECT suspended FROM mcp_event_subscriptions")
            .fetch_one(&f.app.pool)
            .await
            .unwrap();
        assert!(suspended);
        assert!(!run_once(&f.app).await.unwrap());
        subscribe(&f.app, &f.grant, &p).await.unwrap();
        enqueue(&f.app).await.unwrap();
        f.fake.statuses.lock().unwrap().push_back(413);
        assert!(run_once(&f.app).await.unwrap());
        assert_eq!(application_requests(&f).len(), 2);
        subscribe(&f.app, &f.grant, &p).await.unwrap();
        enqueue(&f.app).await.unwrap();
        sqlx::query("UPDATE mcp_event_outbox SET attempts=7")
            .execute(&f.app.pool)
            .await
            .unwrap();
        f.fake.statuses.lock().unwrap().push_back(503);
        run_once(&f.app).await.unwrap();
        assert_eq!(count(&f, "mcp_event_outbox").await, 0);
        // A crash after the eighth dispatch cannot produce a ninth attempt.
        subscribe(&f.app, &f.grant, &p).await.unwrap();
        enqueue(&f.app).await.unwrap();
        sqlx::query(
            "UPDATE mcp_event_outbox SET attempts=8,lease_id='crashed-final-attempt',lease_until=0",
        )
        .execute(&f.app.pool)
        .await
        .unwrap();
        run_once(&f.app).await.unwrap();
        assert_eq!(application_requests(&f).len(), 3);
        assert_eq!(count(&f, "mcp_event_outbox").await, 0);
        // Restoring an older event log must fail explicitly instead of skipping unread work.
        sqlx::query("UPDATE mcp_event_subscriptions SET transport_cursor=999999 WHERE id=$1")
            .bind(result["id"].as_str().unwrap())
            .execute(&f.app.pool)
            .await
            .unwrap();
        assert_eq!(subscribe(&f.app, &f.grant, &p).await.unwrap_err().0, 409);
        assert!(!run_once(&f.app).await.unwrap());
        let reason: String = sqlx::query_scalar("SELECT last_error FROM mcp_event_subscriptions")
            .fetch_one(&f.app.pool)
            .await
            .unwrap();
        assert_eq!(reason, "checkpoint_ahead");
        assert_eq!(application_requests(&f).len(), 3);
    }

    #[tokio::test]
    #[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
    async fn unsubscribe_during_callback_is_unblocked_and_fences_stale_completion() {
        let f = fixture().await;
        let p = params(&f.generation);
        subscribe(&f.app, &f.grant, &p).await.unwrap();
        event(&f, false).await;
        let pause = Arc::new(Pause {
            entered: tokio::sync::Notify::new(),
            resume: tokio::sync::Notify::new(),
        });
        *f.fake.pause.lock().unwrap() = Some(pause.clone());
        let app = f.app.clone();
        let worker = tokio::spawn(async move { run_once(&app).await });
        tokio::time::timeout(Duration::from_secs(2), pause.entered.notified())
            .await
            .unwrap();
        // The attempt budget is durable before dispatch, including a process crash.
        let attempts: i32 = sqlx::query_scalar("SELECT attempts FROM mcp_event_outbox")
            .fetch_one(&f.app.pool)
            .await
            .unwrap();
        assert_eq!(attempts, 1);
        // A second worker cannot dispatch an actively leased occurrence.
        assert!(!run_once(&f.app).await.unwrap());
        // This needs the global writer lock: success proves outbound I/O released it.
        tokio::time::timeout(
            Duration::from_secs(2),
            unsubscribe(&f.app, &f.grant, &unsub(&p)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(count(&f, "mcp_event_outbox").await, 0);
        subscribe(&f.app, &f.grant, &p).await.unwrap();
        enqueue(&f.app).await.unwrap();
        let replacement: String = sqlx::query_scalar("SELECT event_id FROM mcp_event_outbox")
            .fetch_one(&f.app.pool)
            .await
            .unwrap();
        assert_ne!(replacement, application_requests(&f)[0].0);
        pause.resume.notify_one();
        worker.await.unwrap().unwrap();
        // A stale successful response cannot consume a replacement subscription's job.
        assert_eq!(count(&f, "mcp_event_outbox").await, 1);
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT event_id FROM mcp_event_outbox")
                .fetch_one(&f.app.pool)
                .await
                .unwrap(),
            replacement
        );
        run_once(&f.app).await.unwrap();
        assert_eq!(application_requests(&f).len(), 2);
        assert_eq!(count(&f, "mcp_event_outbox").await, 0);
    }
    #[tokio::test]
    #[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
    async fn grant_revoke_atomically_cancels_jobs_and_verification_cache() {
        let f = fixture().await;
        subscribe(&f.app, &f.grant, &params(&f.generation))
            .await
            .unwrap();
        subscribe(&f.app, &f.other, &params(&f.other_generation))
            .await
            .unwrap();
        event(&f, false).await;
        enqueue(&f.app).await.unwrap();
        assert_eq!(count(&f, "mcp_event_outbox").await, 2);
        let mut tx = write_tx(&f.app.pool).await.unwrap();
        oauth::revoke_grant_tx(&mut tx, &f.grant.id).await.unwrap();
        tx.commit().await.unwrap();
        assert_eq!(count(&f, "mcp_event_subscriptions").await, 1);
        assert_eq!(count(&f, "mcp_event_outbox").await, 1);
        assert_eq!(count(&f, "mcp_callback_verifications").await, 1);
        run_once(&f.app).await.unwrap();
        let sent = application_requests(&f);
        assert_eq!(sent.len(), 1);
        assert!(sent[0].1.contains(&f.other_generation));
        assert!(!sent[0].1.contains(&f.generation));
    }

    #[tokio::test]
    #[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
    async fn corrupt_secret_quarantines_only_its_subscription() {
        let f = fixture().await;
        let first = subscribe(&f.app, &f.grant, &params(&f.generation))
            .await
            .unwrap();
        subscribe(&f.app, &f.other, &params(&f.other_generation))
            .await
            .unwrap();
        event(&f, false).await;
        enqueue(&f.app).await.unwrap();
        sqlx::query("UPDATE mcp_event_subscriptions SET secret_cipher=$2 WHERE id=$1")
            .bind(first["id"].as_str().unwrap())
            .bind(vec![0u8; 8])
            .execute(&f.app.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE mcp_event_outbox SET next_attempt=0 WHERE subscription_id=$1")
            .bind(first["id"].as_str().unwrap())
            .execute(&f.app.pool)
            .await
            .unwrap();
        run_once(&f.app).await.unwrap();
        assert!(application_requests(&f).is_empty());
        let reason: String =
            sqlx::query_scalar("SELECT last_error FROM mcp_event_subscriptions WHERE id=$1")
                .bind(first["id"].as_str().unwrap())
                .fetch_one(&f.app.pool)
                .await
                .unwrap();
        assert_eq!(reason, "secret_unavailable");
        assert_eq!(count(&f, "mcp_event_outbox").await, 1);
        run_once(&f.app).await.unwrap();
        assert_eq!(application_requests(&f).len(), 1);
        let ack: i64 = sqlx::query_scalar(
            "SELECT acknowledged_cursor FROM notification_subscriptions WHERE account=$1",
        )
        .bind(&f.grant.account)
        .fetch_one(&f.app.pool)
        .await
        .unwrap();
        assert_eq!(ack, 0);
    }
}
