//! Durable account-owned queues with explicit cumulative ACKs. SSE is only a hint.
use super::*;
use axum::response::sse::{Event, Sse};
use std::convert::Infallible;

const PREFIX: &str = "/api/v1/subscriptions";
const MAX_SUBSCRIPTIONS: i64 = 8;
const POLL_SECONDS: u64 = 1;
const RECONNECT_SECONDS: u64 = 900;

pub(super) enum Route {
    List,
    Subscription(String),
    Events(String),
    Ack(String),
    Stream(String),
}
impl Route {
    pub(super) fn is_write(&self, method: &str) -> bool {
        matches!(
            (self, method),
            (Self::Subscription(_), "PUT" | "DELETE") | (Self::Ack(_), "POST")
        )
    }
}
pub(super) fn route(path: &str) -> Result<Option<Route>> {
    if path == PREFIX {
        return Ok(Some(Route::List));
    }
    let Some(suffix) = path.strip_prefix(&format!("{PREFIX}/")) else {
        return Ok(None);
    };
    let parts = suffix.split('/').collect::<Vec<_>>();
    let name = parts[0];
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
    {
        return Err(err(
            400,
            "Subscription names require 1-64 lowercase letters, digits, underscores, or hyphens",
        ));
    }
    Ok(Some(match parts.as_slice() {
        [_] => Route::Subscription(name.into()),
        [_, "events"] => Route::Events(name.into()),
        [_, "ack"] => Route::Ack(name.into()),
        [_, "stream"] => Route::Stream(name.into()),
        _ => return Err(err(404, "Route not found")),
    }))
}
fn metadata(row: &sqlx::postgres::PgRow) -> Value {
    json!({"generation":row.get::<String,_>("generation"),"name":row.get::<String,_>("name"),"senders":row.get::<Vec<String>,_>("senders"),"visibility":row.get::<String,_>("visibility"),"acknowledgedCursor":row.get::<i64,_>("acknowledged_cursor").to_string(),"deliveredCursor":row.get::<i64,_>("delivered_cursor").to_string(),"created":row.get::<String,_>("created")})
}
async fn subscription(tx: &mut Tx<'_>, who: &str, name: &str) -> Result<sqlx::postgres::PgRow> {
    sqlx::query("SELECT * FROM notification_subscriptions WHERE account=$1 AND name=$2")
        .bind(who)
        .bind(name)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_error)?
        .ok_or_else(|| err(404, "Subscription not found"))
}
fn cursor(body: &Value) -> Result<i64> {
    let text = body["cursor"]
        .as_str()
        .ok_or_else(|| err(400, "Cursor must be a decimal string"))?;
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(err(400, "Cursor must be a decimal string"));
    }
    text.parse::<i64>().map_err(|_| err(400, "Invalid cursor"))
}

pub(super) async fn write(
    app: &Production,
    route: Route,
    headers: &HeaderMap,
    body: &Value,
    method: &str,
) -> Result<Value> {
    let mut tx = write_tx(&app.pool).await?;
    let who = actor_tx(&mut tx, headers).await?;
    let result = match route {
        Route::Subscription(name) if method == "PUT" => {
            object_fields(body, &["senders", "visibility"])?;
            let senders = body["senders"]
                .as_array()
                .filter(|v| (1..=32).contains(&v.len()))
                .ok_or_else(|| err(400, "Choose 1-32 sender UUIDs"))?;
            let mut people = Vec::with_capacity(senders.len());
            for sender in senders {
                let id = uuid(sender.as_str().unwrap_or(""))?;
                if id == who || people.iter().any(|p| p == id) {
                    return Err(err(400, "Duplicate or own sender UUID"));
                }
                people.push(id.to_string());
            }
            people.sort();
            let visibility = body["visibility"]
                .as_str()
                .filter(|s| matches!(*s, "public" | "private" | "all"))
                .ok_or_else(|| err(400, "Visibility must be public, private, or all"))?;
            if let Some(row) =
                sqlx::query("SELECT * FROM notification_subscriptions WHERE account=$1 AND name=$2")
                    .bind(&who)
                    .bind(&name)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(db_error)?
            {
                if row.get::<Vec<String>, _>("senders") != people
                    || row.get::<String, _>("visibility") != visibility
                {
                    return Err(err(
                        409,
                        "Subscription filters are immutable; choose a new name",
                    ));
                }
                // A retry cannot reset progress or consume another account write.
                metadata(&row)
            } else {
                let count: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM notification_subscriptions WHERE account=$1",
                )
                .bind(&who)
                .fetch_one(&mut *tx)
                .await
                .map_err(db_error)?;
                if count >= MAX_SUBSCRIPTIONS {
                    return Err(err(409, "Subscription limit reached"));
                }
                let found: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM accounts WHERE id=ANY($1)")
                        .bind(&people)
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(db_error)?;
                if found != people.len() as i64 {
                    return Err(err(404, "Sender account not found"));
                }
                actor_rate(&mut tx, &who).await?;
                let row = sqlx::query("INSERT INTO notification_subscriptions(account,name,senders,visibility,created,generation) VALUES($1,$2,$3,$4,$5,$6) RETURNING *")
                    .bind(&who).bind(&name).bind(&people).bind(visibility).bind(now()).bind(Uuid::new_v4().to_string())
                    .fetch_one(&mut *tx).await.map_err(db_error)?;
                metadata(&row)
            }
        }
        Route::Subscription(name) if method == "DELETE" => {
            object_fields(body, &["generation"])?;
            let generation = uuid(body["generation"].as_str().unwrap_or(""))?;
            let existing = sqlx::query(
                "SELECT generation FROM notification_subscriptions WHERE account=$1 AND name=$2",
            )
            .bind(&who)
            .bind(&name)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_error)?;
            if existing
                .as_ref()
                .is_some_and(|row| row.get::<String, _>("generation") != generation)
            {
                return Err(err(
                    409,
                    "Subscription generation changed; inspect the current subscription",
                ));
            }
            actor_rate(&mut tx, &who).await?;
            // Idempotent after a lost response; a stale delete cannot remove a replacement.
            sqlx::query("DELETE FROM notification_subscriptions WHERE account=$1 AND name=$2")
                .bind(&who)
                .bind(&name)
                .execute(&mut *tx)
                .await
                .map_err(db_error)?;
            json!({"name":name,"generation":generation,"deleted":true})
        }
        Route::Ack(name) => {
            object_fields(body, &["cursor", "generation"])?;
            let generation = uuid(body["generation"].as_str().unwrap_or(""))?;
            let requested = cursor(body)?;
            let row = subscription(&mut tx, &who, &name).await?;
            if row.get::<String, _>("generation") != generation {
                return Err(err(
                    409,
                    "Subscription generation changed; inspect the current subscription",
                ));
            }
            let delivered: i64 = row.get("delivered_cursor");
            let acknowledged: i64 = row.get("acknowledged_cursor");
            if requested > delivered {
                return Err(err(
                    409,
                    "Cannot acknowledge beyond the delivered watermark",
                ));
            }
            if requested > acknowledged {
                actor_rate(&mut tx, &who).await?;
                let row = sqlx::query("UPDATE notification_subscriptions SET acknowledged_cursor=$3 WHERE account=$1 AND name=$2 RETURNING *")
                    .bind(&who).bind(&name).bind(requested).fetch_one(&mut *tx).await.map_err(db_error)?;
                metadata(&row)
            } else {
                metadata(&row)
            }
        }
        _ => return Err(err(404, "Route not found")),
    };
    tx.commit().await.map_err(db_error)?;
    Ok(result)
}

// Use the same eligibility predicate for durable drain and live hints. No private
// membership is granted by choosing a sender, a name, or an SSE Last-Event-ID.
const ELIGIBLE: &str = "ev.kind='entry.created' AND NOT e.redacted AND e.author=ANY(s.senders) AND e.author<>s.account AND (s.visibility='all' OR c.visibility=s.visibility) AND (c.visibility='public' OR EXISTS(SELECT 1 FROM participants p WHERE p.conversation=c.id AND p.account=s.account)) AND NOT EXISTS(SELECT 1 FROM blocks b WHERE (b.blocker=s.account AND b.blocked=e.author) OR (b.blocker=e.author AND b.blocked=s.account))";

pub(super) async fn read(
    app: &Production,
    route: Route,
    url: &Url,
    headers: &HeaderMap,
) -> Result<Response> {
    if let Route::Stream(name) = route {
        if url.query().is_some() {
            return Err(err(400, "Stream does not accept query parameters"));
        }
        return stream(app, name, headers).await;
    }
    if let Route::Events(name) = route {
        let mut limit = 100i64;
        let mut seen = false;
        for (key, value) in url.query_pairs() {
            if key != "limit" || seen {
                return Err(err(
                    400,
                    "Only one limit parameter is accepted; cursor is stored by the server",
                ));
            }
            seen = true;
            limit = crate::number(Some(&value), 100, 100)?;
        }
        return Ok(axum::Json(events(app, headers, &name, limit).await?).into_response());
    }
    if url.query().is_some() {
        return Err(err(400, "Subscriptions do not accept query parameters"));
    }
    let mut tx = app.pool.begin().await.map_err(db_error)?;
    let who = actor_tx(&mut tx, headers).await?;
    let value = match route {
        Route::List => {
            let rows = sqlx::query(
                "SELECT * FROM notification_subscriptions WHERE account=$1 ORDER BY name LIMIT 8",
            )
            .bind(&who)
            .fetch_all(&mut *tx)
            .await
            .map_err(db_error)?;
            json!({"items":rows.iter().map(metadata).collect::<Vec<_>>()})
        }
        Route::Subscription(name) => metadata(&subscription(&mut tx, &who, &name).await?),
        _ => return Err(err(404, "Route not found")),
    };
    Ok(axum::Json(value).into_response())
}
async fn events(app: &Production, headers: &HeaderMap, name: &str, limit: i64) -> Result<Value> {
    // The writer lock binds the checkpoint, high watermark, ACL and selected rows
    // to one serialized operation, including concurrent ACKs, blocks and revocation.
    let mut tx = write_tx(&app.pool).await?;
    let who = actor_tx(&mut tx, headers).await?;
    let row = subscription(&mut tx, &who, name).await?;
    let acknowledged: i64 = row.get("acknowledged_cursor");
    let high: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(id),0) FROM events")
        .fetch_one(&mut *tx)
        .await
        .map_err(db_error)?;
    if acknowledged > high || row.get::<i64, _>("delivered_cursor") > high {
        return Err(err(
            409,
            "Subscription checkpoint is ahead of this database; operator reconciliation is required",
        ));
    }
    // Separate persisted read budget, across replicas. Stream probes have their own
    // strict per-process connection bound and do not consume this budget.
    let count: i32 = sqlx::query_scalar("INSERT INTO rate_windows(actor,window_start,count) VALUES($1,$2,1) ON CONFLICT(actor) DO UPDATE SET window_start=$2,count=CASE WHEN rate_windows.window_start=$2 THEN rate_windows.count+1 ELSE 1 END RETURNING count")
        .bind(format!("notifications:{who}")).bind(unix()/60).fetch_one(&mut *tx).await.map_err(db_error)?;
    if count > 120 {
        return Err(err(
            429,
            "Notification read rate exceeded; retry after 60 seconds",
        ));
    }
    let query = format!(
        "SELECT ev.id AS cursor,ev.kind,ev.created AS event_created,e.*,c.title,c.visibility FROM notification_subscriptions s JOIN events ev ON ev.id>s.acknowledged_cursor JOIN entries e ON e.id=ev.entry JOIN conversations c ON c.id=ev.conversation WHERE s.account=$1 AND s.name=$2 AND ev.id<=$3 AND {ELIGIBLE} ORDER BY ev.id LIMIT $4"
    );
    let rows = sqlx::query(&query)
        .bind(&who)
        .bind(name)
        .bind(high)
        .bind(limit + 1)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_error)?;
    let more = rows.len() > limit as usize;
    let items = rows.iter().take(limit as usize).map(|row| json!({"cursor":row.get::<i64,_>("cursor").to_string(),"type":row.get::<String,_>("kind"),"created":row.get::<String,_>("event_created"),"conversation":{"id":row.get::<String,_>("conversation"),"title":row.get::<String,_>("title"),"visibility":row.get::<String,_>("visibility")},"entry":entry(row)})).collect::<Vec<_>>();
    let next = if more {
        rows[limit as usize - 1].get::<i64, _>("cursor")
    } else {
        high
    };
    let row = sqlx::query("UPDATE notification_subscriptions SET delivered_cursor=GREATEST(delivered_cursor,$3) WHERE account=$1 AND name=$2 RETURNING *")
        .bind(&who).bind(name).bind(next).fetch_one(&mut *tx).await.map_err(db_error)?;
    let result = json!({"subscription":metadata(&row),"items":items,"nextCursor":next.to_string(),"hasMore":more});
    tx.commit().await.map_err(db_error)?;
    Ok(result)
}

struct StreamGuard {
    streams: Arc<Mutex<HashMap<String, usize>>>,
    who: String,
}
impl Drop for StreamGuard {
    fn drop(&mut self) {
        if let Ok(mut streams) = self.streams.lock()
            && let Some(count) = streams.get_mut(&self.who)
        {
            *count -= 1;
            if *count == 0 {
                streams.remove(&self.who);
            }
        }
    }
}
fn stream_guard(app: &Production, who: &str) -> Result<StreamGuard> {
    let mut streams = app
        .streams
        .lock()
        .map_err(|_| err(503, "Stream capacity unavailable"))?;
    if streams.values().sum::<usize>() >= 32 || streams.get(who).copied().unwrap_or(0) >= 2 {
        return Err(err(429, "Live stream limit reached; use durable polling"));
    }
    *streams.entry(who.to_string()).or_default() += 1;
    Ok(StreamGuard {
        streams: app.streams.clone(),
        who: who.into(),
    })
}
struct Live {
    app: Production,
    headers: HeaderMap,
    name: String,
    who: String,
    generation: String,
    guard: StreamGuard,
    deadline: Instant,
    last: Option<i64>,
    done: bool,
}
async fn probe(live: &Live) -> Result<i64> {
    let mut tx = live.app.pool.begin().await.map_err(db_error)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    if actor_tx(&mut tx, &live.headers).await? != live.who {
        return Err(err(401, "Credential changed"));
    }
    let current = subscription(&mut tx, &live.who, &live.name).await?;
    if current.get::<String, _>("generation") != live.generation {
        return Err(err(
            409,
            "Subscription generation changed; inspect the current subscription",
        ));
    }
    let query = format!(
        "SELECT COALESCE(MAX(ev.id),0) FROM notification_subscriptions s JOIN events ev ON ev.id>s.acknowledged_cursor JOIN entries e ON e.id=ev.entry JOIN conversations c ON c.id=ev.conversation WHERE s.account=$1 AND s.name=$2 AND {ELIGIBLE}"
    );
    sqlx::query_scalar(&query)
        .bind(&live.who)
        .bind(&live.name)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_error)
}
async fn stream(app: &Production, name: String, headers: &HeaderMap) -> Result<Response> {
    let mut tx = app.pool.begin().await.map_err(db_error)?;
    let who = actor_tx(&mut tx, headers).await?;
    let current = subscription(&mut tx, &who, &name).await?;
    let generation = current.get::<String, _>("generation");
    tx.commit().await.map_err(db_error)?;
    let guard = stream_guard(app, &who)?;
    let live = Live {
        app: app.clone(),
        headers: headers.clone(),
        name,
        who,
        generation,
        guard,
        deadline: Instant::now() + Duration::from_secs(RECONNECT_SECONDS),
        last: None,
        done: false,
    };
    // Demand-driven, no producer task or unbounded queue. Only one hint exists at
    // a time; if the client is slow, reconnect and drain the durable queue.
    // The 900s reconnect is demand-driven, not a hard socket deadline: operators
    // must set proxy write/idle deadlines for permanently backpressured peers.
    let stream = futures_util::stream::unfold(live, |mut live| async move {
        if live.done {
            return None;
        }
        let _guard = &live.guard;
        let event = if live.last.is_none() {
            live.last = Some(0);
            Event::default()
                .event("ready")
                .retry(Duration::from_secs(2))
                .data(json!({"subscription":live.name,"generation":live.generation,"pollSeconds":POLL_SECONDS}).to_string())
        } else {
            tokio::time::sleep(Duration::from_secs(POLL_SECONDS)).await;
            if Instant::now() >= live.deadline {
                live.done = true;
                Event::default().event("reconnect").data("{}")
            } else {
                match probe(&live).await {
                    Ok(cursor) => {
                        let changed = live.last != Some(cursor);
                        live.last = Some(cursor);
                        if cursor > 0 && changed {
                            Event::default().event("available").data(
                                json!({"subscription":live.name,"generation":live.generation})
                                    .to_string(),
                            )
                        } else {
                            Event::default().comment("keep-alive")
                        }
                    }
                    Err(error) => {
                        live.done = true;
                        Event::default()
                            .event("error")
                            .data(json!({"status":error.0,"error":error.1}).to_string())
                    }
                }
            }
        };
        Some((Ok::<_, Infallible>(event), live))
    });
    let mut response = Sse::new(stream).into_response();
    response.headers_mut().insert(
        "x-accel-buffering",
        axum::http::HeaderValue::from_static("no"),
    );
    Ok(response)
}
pub(super) fn discovery() -> Value {
    json!({"subscriptions":"/subscriptions","subscription":"/subscriptions/{name}","create":{"method":"PUT","fields":["senders","visibility"],"immutableFilters":true,"initialAcknowledgedCursor":"0"},"events":"/subscriptions/{name}/events?limit=100","ack":{"method":"POST","path":"/subscriptions/{name}/ack","body":{"cursor":"decimal string returned as nextCursor","generation":"exact subscription.generation from that events page"},"when":"only after durable consumer processing","semantics":"cumulative, monotonic, retry-safe, never beyond deliveredCursor"},"delete":{"method":"DELETE","path":"/subscriptions/{name}","body":{"generation":"exact subscription.generation being deleted"}},"live":{"path":"/subscriptions/{name}/stream","transport":"authenticated SSE","events":["ready","available","reconnect","error"],"purpose":"active listener hints; always drain durable events","lastEventId":"ignored; never changes delivery or acknowledgment","pollSeconds":POLL_SECONDS,"reconnectAfterSeconds":RECONNECT_SECONDS,"hardTransportDeadline":false,"maximumPerAccountPerProcess":2,"maximumPerProcess":32,"offlineWake":false,"callbacks":false},"maximumSubscriptions":MAX_SUBSCRIPTIONS,"maximumSenders":32,"maximumEventReadsPerAccountPerMinute":120,"delivery":"at-least-once until explicit ACK; reads and live hints never ACK","recovery":"list subscriptions on the same account after losing client state; credentials may rotate without changing ownership","filters":"entry.created only; selected senders and visibility; exclude own entries, redacted entries, blocked pairs and inaccessible private conversations","filterTiming":"current authorization and block state at read time; ACK also advances past excluded history"})
}
