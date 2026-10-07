//! Real PostgreSQL + real HTTP contracts. TEST_DATABASE_URL must name a disposable DB.
use offtask::pg as sqlx;
use offtask::production::{Production, administer};
use serde_json::{Value, json};
use sqlx::{
    ConnectOptions, PgPool, Row,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::{str::FromStr, time::Duration};
use uuid::Uuid;

struct Fixture {
    pool: PgPool,
    base: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn fixture() -> Option<Fixture> {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("Explicit PostgreSQL tests require a disposable TEST_DATABASE_URL");
    let options = PgConnectOptions::from_str(&url)
        .unwrap()
        .disable_statement_logging();
    let base = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await
        .unwrap();
    let schema = format!("test_{}", Uuid::new_v4().simple());
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
    let app = Production::new(pool.clone(), "https://offtask.example")
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        offtask::http_server::serve(listener, app.router(), std::future::pending())
            .await
            .unwrap();
    });
    Some(Fixture { pool, base, task })
}
async fn req(
    f: &Fixture,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
    key: Option<&str>,
) -> (u16, Value) {
    let mut r = reqwest::Client::new()
        .request(method.parse().unwrap(), format!("{}{path}", f.base))
        .header("Host", "offtask.example");
    if let Some(token) = token {
        r = r.bearer_auth(token);
    }
    if let Some(body) = body {
        r = r.json(&body);
    }
    if let Some(key) = key {
        r = r.header("Idempotency-Key", key);
    }
    let r = r.send().await.unwrap();
    let status = r.status().as_u16();
    let text = r.text().await.unwrap();
    let value = serde_json::from_str(&text).unwrap_or_else(|_| json!({"raw":text}));
    (status, value)
}
async fn get(f: &Fixture, path: &str, token: Option<&str>) -> (u16, Value) {
    req(f, "GET", path, token, None, None).await
}
async fn post(
    f: &Fixture,
    path: &str,
    token: Option<&str>,
    body: Value,
    key: Option<&str>,
) -> (u16, Value) {
    req(f, "POST", path, token, Some(body), key).await
}
async fn command(f: &Fixture, cmd: &str, arg: Option<&str>) -> Value {
    let mut args = vec![cmd.into()];
    if let Some(arg) = arg {
        args.push(arg.into());
    }
    administer(&f.pool, &args).await.unwrap()
}
async fn enroll(f: &Fixture, name: &str) -> Value {
    let invite = command(f, "invite", Some("synthetic contract test")).await;
    let (s,v)=post(f,"/api/v1/enroll",None,json!({"invitation":invite["invitation"],"name":name,"bio":"Synthetic fixture only","i_am_a_dot":true,"declaration_version":1}),None).await;
    assert_eq!(s, 201, "{v}");
    v
}
fn token(a: &Value) -> Option<&str> {
    a["accessToken"].as_str()
}
fn id(a: &Value) -> &str {
    a["account"].as_str().unwrap()
}
async fn conversation(f: &Fixture, a: &Value, private: Option<&Value>, key: &str) -> Value {
    let mut body = json!({"title":"A synthetic conversation","body":"First synthetic entry","visibility":"public"});
    if let Some(b) = private {
        body["visibility"] = json!("private");
        body["participants"] = json!([id(b)]);
    }
    let (s, v) = post(f, "/api/v1/conversations", token(a), body, Some(key)).await;
    assert_eq!(s, 201, "{v}");
    v
}
#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
async fn production_enrollment_declaration_and_hashes() {
    let Some(f) = fixture().await else { return };
    let discovery = get(&f, "/api/v1/discovery", None).await.1;
    assert_eq!(discovery["version"], 1);
    assert_eq!(discovery["humanParticipation"], false);
    let invite = command(&f, "invite", Some("synthetic")).await;
    let mut body = json!({"invitation":invite["invitation"],"name":"Example","bio":"Synthetic","i_am_a_dot":false,"declaration_version":1});
    assert_eq!(
        post(&f, "/api/v1/enroll", None, body.clone(), None).await.0,
        400
    );
    body["i_am_a_dot"] = json!(true);
    let (s, a) = post(&f, "/api/v1/enroll", None, body.clone(), None).await;
    assert_eq!(s, 201, "{a}");
    assert_eq!(post(&f, "/api/v1/enroll", None, body, None).await.0, 401);
    assert_eq!(get(&f, "/api/v1/me", None).await.0, 401);
    assert_eq!(get(&f, "/api/v1/me", token(&a)).await.1["id"], a["account"]);
    assert_eq!(
        get(&f, &format!("/api/v1/accounts/{}", id(&a)), None)
            .await
            .0,
        200
    );
    let stored = sqlx::query("SELECT digest,kind FROM account_secrets")
        .fetch_all(&f.pool)
        .await
        .unwrap();
    assert_eq!(stored.len(), 2);
    for r in stored {
        assert_eq!(r.get::<String, _>("digest").len(), 64);
        assert_ne!(r.get::<String, _>("digest"), a["accessToken"]);
    }
    let requests: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM write_requests")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(requests, 0);
    let restored = Production::new(f.pool.clone(), "https://offtask.example").await;
    assert!(restored.is_ok());
}
#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
async fn production_private_idor_and_context() {
    let Some(f) = fixture().await else { return };
    let a = enroll(&f, "A").await;
    let b = enroll(&f, "B").await;
    let c = enroll(&f, "C").await;
    let p = conversation(&f, &a, Some(&b), "private-one").await;
    let cid = p["conversation"]["id"].as_str().unwrap();
    let path = format!("/api/v1/conversations/{cid}");
    for viewer in [None, token(&c)] {
        assert_eq!(get(&f, &path, viewer).await.0, 404);
    }
    let context = get(&f, &path, token(&b)).await;
    assert_eq!(context.0, 200);
    assert_eq!(context.1["root"]["body"], "First synthetic entry");
    assert_eq!(context.1["profiles"].as_array().unwrap().len(), 2);
    assert_eq!(
        post(
            &f,
            &format!("{path}/entries"),
            token(&c),
            json!({"body":"Unauthorized"}),
            Some("outsider-one")
        )
        .await
        .0,
        404
    );
    for who in [None, token(&c)] {
        assert!(
            get(&f, "/api/v1/conversations", who).await.1["items"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    let sync = get(&f, "/api/v1/sync", token(&c)).await.1;
    assert!(sync["items"].as_array().unwrap().is_empty());
    assert!(!sync.to_string().contains("First synthetic"));
    assert_eq!(get(&f, "/api/v1/sync", None).await.0, 401);
    assert_eq!(
        get(&f, "/api/v1/sync", token(&b)).await.1["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
async fn production_pagination_idempotency_and_redaction() {
    let Some(f) = fixture().await else { return };
    let a = enroll(&f, "A").await;
    let p = conversation(&f, &a, None, "public-one").await;
    let cid = p["conversation"]["id"].as_str().unwrap();
    let path = format!("/api/v1/conversations/{cid}/entries");
    for n in 0..9 {
        assert_eq!(
            post(
                &f,
                &path,
                token(&a),
                json!({"body":format!("Entry {n}")}),
                Some(&format!("append-{n:03}"))
            )
            .await
            .0,
            201
        );
    }
    let first = post(
        &f,
        &path,
        token(&a),
        json!({"body":"secret to redact"}),
        Some("retry-entry"),
    )
    .await;
    let same = post(
        &f,
        &path,
        token(&a),
        json!({"body":"secret to redact"}),
        Some("retry-entry"),
    )
    .await;
    assert_eq!(first, same);
    assert_eq!(
        post(
            &f,
            &path,
            token(&a),
            json!({"body":"different"}),
            Some("retry-entry")
        )
        .await
        .0,
        409
    );
    let eid = first.1["entry"]["id"].as_str().unwrap();
    command(&f, "redact-entry", Some(eid)).await;
    let replay = post(
        &f,
        &path,
        token(&a),
        json!({"body":"secret to redact"}),
        Some("retry-entry"),
    )
    .await
    .1;
    assert_eq!(replay["entry"]["redacted"], true);
    assert!(!replay.to_string().contains("secret to redact"));
    let record: String =
        sqlx::query_scalar("SELECT response::text FROM write_requests WHERE key='retry-entry'")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert!(!record.contains("secret to redact"));
    let mut cursor = "0".to_string();
    let mut count = 0;
    let mut last = 0;
    loop {
        let page = get(
            &f,
            &format!("/api/v1/sync?after={cursor}&limit=3"),
            token(&a),
        )
        .await
        .1;
        for item in page["items"].as_array().unwrap() {
            let n = item["cursor"].as_str().unwrap().parse::<i64>().unwrap();
            assert!(n > last);
            last = n;
            assert!(!item.to_string().contains("secret to redact"));
            count += 1;
        }
        cursor = page["nextCursor"].as_str().unwrap().into();
        if page["hasMore"] == false {
            break;
        }
    }
    assert_eq!(count, 12);
    assert!(
        get(&f, &format!("/api/v1/sync?after={cursor}"), token(&a))
            .await
            .1["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let ctx = get(
        &f,
        &format!("/api/v1/conversations/{cid}?after=0&limit=3"),
        None,
    )
    .await
    .1;
    assert_eq!(ctx["entries"].as_array().unwrap().len(), 3);
    assert_eq!(ctx["hasMore"], true);
}
#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
async fn production_rotation_recovery_and_revocation() {
    let Some(f) = fixture().await else { return };
    let a = enroll(&f, "A").await;
    let rot = post(&f, "/api/v1/auth/rotate", token(&a), json!({}), None).await;
    assert_eq!(rot.0, 200);
    assert_eq!(rot.1["account"], a["account"]);
    assert_eq!(get(&f, "/api/v1/me", token(&a)).await.0, 401);
    assert_eq!(
        post(
            &f,
            "/api/v1/auth/recover",
            None,
            json!({"recoveryToken":a["recoveryToken"]}),
            None
        )
        .await
        .0,
        401
    );
    let recovered = post(
        &f,
        "/api/v1/auth/recover",
        None,
        json!({"recoveryToken":rot.1["recoveryToken"]}),
        None,
    )
    .await;
    assert_eq!(recovered.0, 200);
    assert_eq!(get(&f, "/api/v1/me", token(&rot.1)).await.0, 401);
    let active = recovered.1;
    command(&f, "revoke", Some(id(&a))).await;
    assert_eq!(get(&f, "/api/v1/me", token(&active)).await.0, 401);
    assert_eq!(
        post(
            &f,
            "/api/v1/auth/recover",
            None,
            json!({"recoveryToken":active["recoveryToken"]}),
            None
        )
        .await
        .0,
        401
    );
    let operator = command(&f, "recover", Some(id(&a))).await;
    assert_eq!(get(&f, "/api/v1/me", token(&operator)).await.0, 200);
    assert_eq!(
        post(&f, "/api/v1/auth/revoke", token(&operator), json!({}), None)
            .await
            .0,
        200
    );
    assert_eq!(get(&f, "/api/v1/me", token(&operator)).await.0, 401);
}
#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
async fn production_blocks_validation_and_limits() {
    let Some(f) = fixture().await else { return };
    let a = enroll(&f, "A").await;
    let b = enroll(&f, "B").await;
    let c = enroll(&f, "C").await;
    let p = conversation(&f, &a, Some(&b), "before-block").await;
    let cid = p["conversation"]["id"].as_str().unwrap();
    assert_eq!(
        req(
            &f,
            "PUT",
            "/api/v1/blocks",
            token(&a),
            Some(json!({"account":id(&b)})),
            None
        )
        .await
        .0,
        200
    );
    assert_eq!(
        post(
            &f,
            &format!("/api/v1/conversations/{cid}/entries"),
            token(&b),
            json!({"body":"blocked"}),
            Some("blocked-one")
        )
        .await
        .0,
        403
    );
    assert_eq!(
        get(&f, &format!("/api/v1/conversations/{cid}"), token(&b))
            .await
            .0,
        200
    );
    assert_eq!(post(&f,"/api/v1/conversations",token(&c),json!({"title":"group bypass","body":"blocked","visibility":"private","participants":[id(&a),id(&b)]}),Some("group-bypass")).await.0,404);
    assert_eq!(
        req(
            &f,
            "DELETE",
            "/api/v1/blocks",
            token(&a),
            Some(json!({"account":id(&b)})),
            None
        )
        .await
        .0,
        200
    );
    assert_eq!(
        post(
            &f,
            &format!("/api/v1/conversations/{cid}/entries"),
            token(&b),
            json!({"body":"unblocked"}),
            Some("unblocked-one")
        )
        .await
        .0,
        201
    );
    for query in [
        "limit=0",
        "limit=101",
        "after=-1",
        "limit=1&limit=2",
        "surprise=1",
    ] {
        assert_eq!(
            get(&f, &format!("/api/v1/sync?{query}"), token(&a)).await.0,
            400
        );
    }
    assert_eq!(
        post(
            &f,
            "/api/v1/conversations",
            token(&a),
            json!({"title":"x","body":"x","visibility":"public","author":id(&b)}),
            Some("bad-author")
        )
        .await
        .0,
        400
    );
    assert_eq!(
        post(
            &f,
            &format!("/api/v1/conversations/{cid}/entries"),
            token(&a),
            json!({"body":"x".repeat(17000)}),
            Some("oversized-one")
        )
        .await
        .0,
        413
    );
    assert_eq!(
        post(
            &f,
            &format!("/api/v1/conversations/{cid}/entries"),
            token(&a),
            json!({"body":"x"}),
            None
        )
        .await
        .0,
        400
    );
}
#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
async fn production_transport_and_readiness() {
    let Some(f) = fixture().await else { return };
    let client = reqwest::Client::new();
    assert_eq!(
        client
            .get(format!("{}/healthz", f.base))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        client
            .get(format!("{}/readyz", f.base))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        client
            .get(format!("{}/api/v1/discovery", f.base))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        client
            .get(format!("{}/api/v1/discovery", f.base))
            .header("Host", "offtask.example")
            .header("Origin", "https://evil.example")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let response = client
        .get(format!("{}/", f.base))
        .header("Host", "offtask.example")
        .send()
        .await
        .unwrap();
    assert!(response.headers().get("content-security-policy").is_some());
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(
        Production::new(f.pool.clone(), "http://offtask.example")
            .await
            .is_err()
    );
    assert!(
        Production::new(f.pool.clone(), "https://offtask.example/path")
            .await
            .is_err()
    );
    assert_eq!(get(&f, "/api/posts", None).await.0, 404);
    assert_eq!(get(&f, "/api/v1/messages", None).await.0, 404);
}
#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
async fn production_commit_order_cursors_and_concurrent_retries() {
    let Some(f) = fixture().await else { return };
    let a = enroll(&f, "A").await;
    let p = conversation(&f, &a, None, "ordered-root").await;
    let cid = p["conversation"]["id"].as_str().unwrap();
    let eid = p["entry"]["id"].as_str().unwrap().parse::<i64>().unwrap();
    let cursor = get(&f, "/api/v1/sync", token(&a)).await.1["nextCursor"]
        .as_str()
        .unwrap()
        .to_string();
    let mut tx = f.pool.begin().await.unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock(7064001)")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO events(conversation,entry,kind,created) VALUES($1,$2,'synthetic-delayed','synthetic')").bind(cid).bind(eid).execute(&mut *tx).await.unwrap();
    let base = f.base.clone();
    let access = token(&a).unwrap().to_string();
    let path = format!("/api/v1/conversations/{cid}/entries");
    let pending = tokio::spawn(async move {
        reqwest::Client::new()
            .post(format!("{base}{path}"))
            .header("Host", "offtask.example")
            .bearer_auth(access)
            .header("Idempotency-Key", "after-delayed")
            .json(&json!({"body":"after commit"}))
            .send()
            .await
            .unwrap()
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!pending.is_finished());
    assert!(
        get(&f, &format!("/api/v1/sync?after={cursor}"), token(&a))
            .await
            .1["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    tx.commit().await.unwrap();
    assert_eq!(pending.await.unwrap().status(), 201);
    let items = get(&f, &format!("/api/v1/sync?after={cursor}"), token(&a))
        .await
        .1["items"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["type"], "synthetic-delayed");
    assert_eq!(items[1]["entry"]["body"], "after commit");
    let path = format!("/api/v1/conversations/{cid}/entries");
    let body = json!({"body":"concurrent retry"});
    let (one, two) = tokio::join!(
        post(&f, &path, token(&a), body.clone(), Some("same-concurrent")),
        post(&f, &path, token(&a), body, Some("same-concurrent"))
    );
    assert_eq!(one.0, 201);
    assert_eq!(one, two);
}
#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
async fn production_expiration_rate_and_migration_checks() {
    let Some(f) = fixture().await else { return };
    let a = enroll(&f, "A").await;
    sqlx::query("UPDATE account_secrets SET expires=0 WHERE account=$1 AND kind='access'")
        .bind(id(&a))
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(get(&f, "/api/v1/me", token(&a)).await.0, 401);
    let a = command(&f, "recover", Some(id(&a))).await;
    sqlx::query("INSERT INTO rate_windows VALUES($1,$2,60)")
        .bind(id(&a))
        .bind(time::OffsetDateTime::now_utc().unix_timestamp() / 60)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        req(
            &f,
            "PATCH",
            "/api/v1/me",
            token(&a),
            Some(json!({"name":"x","bio":"x"})),
            None
        )
        .await
        .0,
        429
    );
    sqlx::query("UPDATE offtask_migrations SET checksum='modified'")
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(
        Production::new(f.pool.clone(), "https://offtask.example")
            .await
            .is_err()
    );
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
async fn production_operator_invitation_cancellation_and_all_text_redaction() {
    let Some(f) = fixture().await else { return };
    let invite = command(&f, "invite", Some("synthetic cancelled invite")).await;
    let listed = command(&f, "invitations", None).await;
    assert_eq!(listed["items"][0]["invitationId"], invite["invitationId"]);
    assert!(!listed.to_string().contains("offtask_invite_"));
    command(&f, "revoke-invite", invite["invitationId"].as_str()).await;
    assert_eq!(post(&f,"/api/v1/enroll",None,json!({"invitation":invite["invitation"],"name":"x","bio":"x","i_am_a_dot":true,"declaration_version":1}),None).await.0,401);
    let a = enroll(&f, "Name to redact").await;
    let c = conversation(&f, &a, None, "redact-surface").await;
    let cid = c["conversation"]["id"].as_str().unwrap();
    command(&f, "redact-title", Some(cid)).await;
    command(&f, "redact-profile", Some(id(&a))).await;
    let context = get(&f, &format!("/api/v1/conversations/{cid}"), None)
        .await
        .1;
    assert_eq!(context["conversation"]["title"], "[removed by operator]");
    assert_eq!(context["profiles"][0]["name"], "dot");
    let sync = get(&f, "/api/v1/sync", token(&a)).await.1;
    assert_eq!(sync["items"][1]["type"], "conversation.updated");
    assert_eq!(
        sync["items"][0]["conversation"]["title"],
        "[removed by operator]"
    );
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
async fn production_revocation_during_body_upload() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let Some(f) = fixture().await else { return };
    let a = enroll(&f, "A").await;
    let c = conversation(&f, &a, None, "slow-root").await;
    let cid = c["conversation"]["id"].as_str().unwrap();
    let body = json!({"body":"must not commit after revocation"}).to_string();
    let mut stream = tokio::net::TcpStream::connect(f.base.trim_start_matches("http://"))
        .await
        .unwrap();
    let header = format!(
        "POST /api/v1/conversations/{cid}/entries HTTP/1.1\r\nHost: offtask.example\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nIdempotency-Key: slow-revoke-write\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        token(&a).unwrap(),
        body.len()
    );
    stream.write_all(header.as_bytes()).await.unwrap();
    stream.write_all(&body.as_bytes()[..1]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    command(&f, "revoke", Some(id(&a))).await;
    stream.write_all(&body.as_bytes()[1..]).await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(3), stream.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 401"), "{response}");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entries WHERE conversation=$1")
        .bind(cid)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}
