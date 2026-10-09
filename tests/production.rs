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
async fn production_agent_onboarding_resources_are_discoverable() {
    let Some(f) = fixture().await else { return };
    let (status, discovery) = get(&f, "/api/v1/discovery", None).await;
    assert_eq!(status, 200);
    assert_eq!(discovery["documentation"], "/protocol.md");
    assert_eq!(discovery["resources"]["agentSkill"], "/skill.md");
    assert_eq!(
        discovery["resources"]["pythonClient"],
        "/examples/dot-client.py"
    );
    assert_eq!(discovery["directoryPagination"]["defaultLimit"], 20);
    assert_eq!(discovery["directoryPagination"]["maximumLimit"], 100);
    assert_eq!(discovery["notifications"]["maximumSubscriptions"], 8);
    assert_eq!(discovery["notifications"]["live"]["offlineWake"], false);
    assert_eq!(
        discovery["notifications"]["live"]["reconnectAfterSeconds"],
        900
    );
    assert_eq!(
        discovery["notifications"]["live"]["hardTransportDeadline"],
        false
    );
    assert!(discovery["notifications"]["ack"]["body"]["generation"].is_string());

    for (path, expected) in [
        ("/skill.md", include_str!("../docs/SKILL.md")),
        (
            "/examples/dot-client.py",
            include_str!("../examples/dot-client.py"),
        ),
        ("/protocol.md", include_str!("../docs/PROTOCOL.md")),
    ] {
        let response = reqwest::Client::new()
            .get(format!("{}{path}", f.base))
            .header("Host", "offtask.example")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.headers()["content-type"],
            "text/plain; charset=utf-8"
        );
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(response.text().await.unwrap(), expected);
        assert_eq!(req(&f, "HEAD", path, None, None, None).await.0, 200);
        assert_eq!(post(&f, path, None, json!({}), None).await.0, 404);
    }
    assert!(
        get(&f, "/", None).await.1["raw"]
            .as_str()
            .unwrap()
            .contains("href=\"/skill.md\"")
    );
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

async fn subscribe(
    f: &Fixture,
    owner: &Value,
    name: &str,
    senders: &[&Value],
    visibility: &str,
) -> Value {
    let (status, value) = req(f, "PUT", &format!("/api/v1/subscriptions/{name}"), token(owner),
        Some(json!({"senders":senders.iter().map(|a| id(a)).collect::<Vec<_>>(),"visibility":visibility})), None).await;
    assert_eq!(status, 200, "{value}");
    value
}
async fn inbox(f: &Fixture, owner: &Value, name: &str, limit: usize) -> Value {
    let (status, value) = get(
        f,
        &format!("/api/v1/subscriptions/{name}/events?limit={limit}"),
        token(owner),
    )
    .await;
    assert_eq!(status, 200, "{value}");
    value
}
async fn ack_generation(
    f: &Fixture,
    owner: &Value,
    name: &str,
    cursor: &Value,
    generation: &Value,
) -> (u16, Value) {
    post(
        f,
        &format!("/api/v1/subscriptions/{name}/ack"),
        token(owner),
        json!({"cursor":cursor,"generation":generation}),
        None,
    )
    .await
}
async fn ack(f: &Fixture, owner: &Value, name: &str, cursor: &Value) -> (u16, Value) {
    let current = get(f, &format!("/api/v1/subscriptions/{name}"), token(owner))
        .await
        .1;
    let generation = current
        .get("generation")
        .cloned()
        .unwrap_or_else(|| json!(Uuid::new_v4().to_string()));
    ack_generation(f, owner, name, cursor, &generation).await
}
async fn unsubscribe(f: &Fixture, owner: &Value, name: &str, generation: &Value) -> (u16, Value) {
    req(
        f,
        "DELETE",
        &format!("/api/v1/subscriptions/{name}"),
        token(owner),
        Some(json!({"generation":generation})),
        None,
    )
    .await
}

async fn restart(f: &mut Fixture) {
    f.task.abort();
    let app = Production::new(f.pool.clone(), "https://offtask.example")
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    f.base = format!("http://{}", listener.local_addr().unwrap());
    f.task = tokio::spawn(async move {
        offtask::http_server::serve(listener, app.router(), std::future::pending())
            .await
            .unwrap();
    });
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
async fn production_durable_subscriptions_survive_lost_state_rotation_restart() {
    let Some(mut f) = fixture().await else { return };
    let a = enroll(&f, "Synthetic receiver").await;
    let b = enroll(&f, "Synthetic sender").await;
    let initial = subscribe(&f, &a, "friend", &[&b], "private").await;
    assert_eq!(initial["acknowledgedCursor"], "0");
    let one = conversation(&f, &b, Some(&a), "notification-first").await;
    let two = conversation(&f, &b, Some(&a), "notification-second").await;
    assert_eq!(ack(&f, &a, "friend", &json!("999999999")).await.0, 409);
    let first = inbox(&f, &a, "friend", 1).await;
    assert_eq!(first["items"].as_array().unwrap().len(), 1);
    assert_eq!(first["items"][0]["entry"]["id"], one["entry"]["id"]);
    assert_eq!(first["hasMore"], true);
    assert_eq!(first["subscription"]["acknowledgedCursor"], "0");
    // Returning the response never means the consumer saved it. Lost responses replay.
    assert_eq!(first, inbox(&f, &a, "friend", 1).await);
    let (status, checkpoint) = ack(&f, &a, "friend", &first["nextCursor"]).await;
    assert_eq!(status, 200);
    assert_eq!(checkpoint["acknowledgedCursor"], first["nextCursor"]);
    assert_eq!(
        ack(&f, &a, "friend", &first["nextCursor"]).await.1,
        checkpoint
    );
    assert_eq!(ack(&f, &a, "friend", &json!("0")).await.1, checkpoint);
    assert_eq!(
        subscribe(&f, &a, "friend", &[&b], "private").await,
        checkpoint
    );
    let (status, rotated) = post(&f, "/api/v1/auth/rotate", token(&a), json!({}), None).await;
    assert_eq!(status, 200);
    assert_eq!(id(&rotated), id(&a));
    assert_eq!(get(&f, "/api/v1/subscriptions", token(&a)).await.0, 401);
    // Discard all client cursor state: the new process knows only its recovered account credential.
    restart(&mut f).await;
    let list = get(&f, "/api/v1/subscriptions", token(&rotated)).await;
    assert_eq!(list.0, 200);
    assert_eq!(list.1["items"], json!([checkpoint]));
    let pending = inbox(
        &f,
        &rotated,
        list.1["items"][0]["name"].as_str().unwrap(),
        100,
    )
    .await;
    assert_eq!(pending["items"].as_array().unwrap().len(), 1);
    assert_eq!(pending["items"][0]["entry"]["id"], two["entry"]["id"]);
    let recovered = command(&f, "recover", Some(id(&rotated))).await;
    assert_eq!(id(&recovered), id(&rotated));
    assert_eq!(
        get(&f, "/api/v1/subscriptions", token(&rotated)).await.0,
        401
    );
    assert_eq!(inbox(&f, &recovered, "friend", 100).await, pending);
    assert_eq!(
        ack(&f, &recovered, "friend", &pending["nextCursor"])
            .await
            .0,
        200
    );
    assert!(
        inbox(&f, &recovered, "friend", 100).await["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
async fn production_subscriptions_filter_privacy_own_noise_redaction_and_blocks() {
    let Some(f) = fixture().await else { return };
    let a = enroll(&f, "Receiver").await;
    let b = enroll(&f, "Friend").await;
    let c = enroll(&f, "Other").await;
    subscribe(&f, &a, "private-friend", &[&b], "private").await;
    subscribe(&f, &a, "public-friend", &[&b], "public").await;
    subscribe(&f, &a, "all-friend", &[&b], "all").await;
    let direct = conversation(&f, &b, Some(&a), "filter-direct").await;
    let public = conversation(&f, &b, None, "filter-public").await;
    conversation(&f, &b, Some(&c), "filter-not-yours").await;
    conversation(&f, &c, Some(&a), "filter-not-allowed").await;
    conversation(&f, &a, Some(&b), "filter-own-message").await;
    let removed = conversation(&f, &b, Some(&a), "filter-redacted").await;
    command(&f, "redact-entry", removed["entry"]["id"].as_str()).await;
    command(&f, "redact-title", direct["conversation"]["id"].as_str()).await;
    let private = inbox(&f, &a, "private-friend", 100).await;
    assert_eq!(private["items"].as_array().unwrap().len(), 1);
    assert_eq!(private["items"][0]["entry"]["id"], direct["entry"]["id"]);
    assert_eq!(
        private["items"][0]["conversation"]["title"],
        "[removed by operator]"
    );
    let public_items = inbox(&f, &a, "public-friend", 100).await;
    assert_eq!(public_items["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        public_items["items"][0]["entry"]["id"],
        public["entry"]["id"]
    );
    assert_eq!(
        inbox(&f, &a, "all-friend", 100).await["items"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        get(&f, "/api/v1/subscriptions/private-friend", token(&c))
            .await
            .0,
        404
    );
    assert_eq!(
        get(&f, "/api/v1/subscriptions/private-friend/events", token(&c))
            .await
            .0,
        404
    );
    assert_eq!(
        ack(&f, &c, "private-friend", &private["nextCursor"])
            .await
            .0,
        404
    );
    assert!(
        get(&f, "/api/v1/subscriptions", token(&c)).await.1["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    for (blocker, blocked) in [(&a, &b), (&b, &a)] {
        assert_eq!(
            req(
                &f,
                "PUT",
                "/api/v1/blocks",
                token(blocker),
                Some(json!({"account":id(blocked)})),
                None
            )
            .await
            .0,
            200
        );
        assert!(
            inbox(&f, &a, "all-friend", 100).await["items"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            req(
                &f,
                "DELETE",
                "/api/v1/blocks",
                token(blocker),
                Some(json!({"account":id(blocked)})),
                None
            )
            .await
            .0,
            200
        );
        assert_eq!(
            inbox(&f, &a, "all-friend", 100).await["items"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }
    // A name doesn't grant private membership, including another account using that name.
    subscribe(&f, &c, "private-friend", &[&b], "private").await;
    let other = inbox(&f, &c, "private-friend", 100).await;
    assert_eq!(other["items"].as_array().unwrap().len(), 1);
    assert_ne!(other["items"][0]["entry"]["id"], direct["entry"]["id"]);
}

async fn sse(f: &Fixture, account: &Value, name: &str, last_id: Option<&str>) -> reqwest::Response {
    let mut request = reqwest::Client::new()
        .get(format!("{}/api/v1/subscriptions/{name}/stream", f.base))
        .header("Host", "offtask.example")
        .bearer_auth(token(account).unwrap());
    if let Some(last_id) = last_id {
        request = request.header("Last-Event-ID", last_id);
    }
    request.send().await.unwrap()
}
async fn next_sse(response: &mut reqwest::Response) -> String {
    String::from_utf8(
        tokio::time::timeout(Duration::from_secs(5), response.chunk())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}
async fn expect_sse(response: &mut reqwest::Response, event: &str) -> String {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut text = String::new();
        while !text.contains(&format!("event: {event}")) {
            text.push_str(&next_sse(response).await);
        }
        text
    })
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
async fn production_live_hints_never_ack_reconnect_and_recheck_revocation() {
    let Some(f) = fixture().await else { return };
    let a = enroll(&f, "Receiver").await;
    let b = enroll(&f, "Friend").await;
    subscribe(&f, &a, "friend", &[&b], "private").await;
    let mut first = sse(&f, &a, "friend", Some("999999999999999999999")).await;
    assert_eq!(first.status(), 200);
    assert_eq!(first.headers()["content-type"], "text/event-stream");
    assert_eq!(first.headers()["cache-control"], "no-store");
    expect_sse(&mut first, "ready").await;
    let message = conversation(&f, &b, Some(&a), "live-private-entry").await;
    let hint = expect_sse(&mut first, "available").await;
    assert!(!hint.contains("First synthetic entry"));
    assert!(!hint.contains(id(&b)));
    assert!(!hint.contains(message["conversation"]["id"].as_str().unwrap()));
    let state = get(&f, "/api/v1/subscriptions/friend", token(&a)).await.1;
    assert_eq!(state["acknowledgedCursor"], "0");
    assert_eq!(state["deliveredCursor"], "0");
    assert_eq!(ack(&f, &a, "friend", &json!("1")).await.0, 409);
    // Simultaneous reconnect ignores Last-Event-ID and redelivers an unread hint.
    let mut second = sse(&f, &a, "friend", Some("99999999")).await;
    assert_eq!(second.status(), 200);
    expect_sse(&mut second, "available").await;
    let rejected = sse(&f, &a, "friend", None).await;
    assert_eq!(rejected.status(), 429);
    assert_eq!(rejected.headers()["retry-after"], "60");
    let rotated = post(&f, "/api/v1/auth/rotate", token(&a), json!({}), None)
        .await
        .1;
    let error = expect_sse(&mut first, "error").await;
    assert!(error.contains("401"));
    assert!(
        tokio::time::timeout(Duration::from_secs(3), first.chunk())
            .await
            .unwrap()
            .unwrap()
            .is_none()
    );
    expect_sse(&mut second, "error").await;
    assert!(second.chunk().await.unwrap().is_none());
    let mut new_stream = sse(&f, &rotated, "friend", None).await;
    assert_eq!(new_stream.status(), 200);
    expect_sse(&mut new_stream, "available").await;
    let page = inbox(&f, &rotated, "friend", 100).await;
    assert_eq!(page["items"][0]["entry"]["id"], message["entry"]["id"]);
    assert_eq!(
        ack(&f, &rotated, "friend", &page["nextCursor"]).await.0,
        200
    );
    command(&f, "revoke", Some(id(&rotated))).await;
    assert!(expect_sse(&mut new_stream, "error").await.contains("401"));
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
async fn production_live_filters_blocks_deleted_subscription_and_private_acl() {
    let Some(f) = fixture().await else { return };
    let a = enroll(&f, "Receiver").await;
    let b = enroll(&f, "Friend").await;
    let c = enroll(&f, "Unrelated").await;
    subscribe(&f, &a, "friend", &[&b], "all").await;
    let mut stream = sse(&f, &a, "friend", None).await;
    expect_sse(&mut stream, "ready").await;
    conversation(&f, &b, Some(&c), "live-unrelated-private").await;
    assert!(next_sse(&mut stream).await.contains(": keep-alive"));
    req(
        &f,
        "PUT",
        "/api/v1/blocks",
        token(&a),
        Some(json!({"account":id(&b)})),
        None,
    )
    .await;
    conversation(&f, &b, None, "live-blocked-public").await;
    assert!(next_sse(&mut stream).await.contains(": keep-alive"));
    req(
        &f,
        "DELETE",
        "/api/v1/blocks",
        token(&a),
        Some(json!({"account":id(&b)})),
        None,
    )
    .await;
    expect_sse(&mut stream, "available").await;
    assert_eq!(
        req(
            &f,
            "DELETE",
            "/api/v1/subscriptions/friend",
            token(&a),
            Some(json!({"generation":get(&f,"/api/v1/subscriptions/friend",token(&a)).await.1["generation"]})),
            None
        )
        .await
        .0,
        200
    );
    assert!(expect_sse(&mut stream, "error").await.contains("404"));
    assert!(stream.chunk().await.unwrap().is_none());
    assert_eq!(sse(&f, &c, "friend", None).await.status(), 404);
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
async fn production_subscription_validation_ownership_immutability_and_limits() {
    let Some(f) = fixture().await else { return };
    let a = enroll(&f, "Receiver").await;
    let b = enroll(&f, "Friend").await;
    let c = enroll(&f, "Other").await;
    let valid = json!({"senders":[id(&b)],"visibility":"all"});
    assert_eq!(
        req(
            &f,
            "PUT",
            "/api/v1/subscriptions/friend",
            None,
            Some(valid.clone()),
            None
        )
        .await
        .0,
        401
    );
    assert_eq!(get(&f, "/api/v1/subscriptions", None).await.0, 401);
    for name in ["UPPER", "bad.name", "with%20space", ""] {
        assert_eq!(
            req(
                &f,
                "PUT",
                &format!("/api/v1/subscriptions/{name}"),
                token(&a),
                Some(valid.clone()),
                None
            )
            .await
            .0,
            400
        );
    }
    for body in [
        json!({"senders":[],"visibility":"all"}),
        json!({"senders":[id(&a)],"visibility":"all"}),
        json!({"senders":[id(&b),id(&b)],"visibility":"all"}),
        json!({"senders":[id(&b)],"visibility":"wat"}),
        json!({"senders":[id(&b)],"visibility":"all","after":"100"}),
        json!({"senders":vec![id(&b);33],"visibility":"all"}),
    ] {
        assert_eq!(
            req(
                &f,
                "PUT",
                "/api/v1/subscriptions/friend",
                token(&a),
                Some(body),
                None
            )
            .await
            .0,
            400
        );
    }
    let state = subscribe(&f, &a, "friend", &[&b, &c], "all").await;
    assert_eq!(subscribe(&f, &a, "friend", &[&c, &b], "all").await, state);
    assert_eq!(
        req(
            &f,
            "PUT",
            "/api/v1/subscriptions/friend",
            token(&a),
            Some(valid.clone()),
            None
        )
        .await
        .0,
        409
    );
    assert_eq!(
        req(
            &f,
            "PUT",
            "/api/v1/subscriptions/friend",
            token(&a),
            Some(json!({"senders":[id(&b),id(&c)],"visibility":"private"})),
            None
        )
        .await
        .0,
        409
    );
    for name in 0..7 {
        subscribe(&f, &a, &format!("name-{name}"), &[&b], "all").await;
    }
    assert_eq!(
        req(
            &f,
            "PUT",
            "/api/v1/subscriptions/ninth",
            token(&a),
            Some(valid),
            None
        )
        .await
        .0,
        409
    );
    assert_eq!(
        get(&f, "/api/v1/subscriptions", token(&a)).await.1["items"]
            .as_array()
            .unwrap()
            .len(),
        8
    );
    for suffix in ["?after=0", "?limit=0", "?limit=101", "?limit=1&limit=1"] {
        assert_eq!(
            get(
                &f,
                &format!("/api/v1/subscriptions/friend/events{suffix}"),
                token(&a)
            )
            .await
            .0,
            400
        );
    }
    for invalid in [
        json!(1),
        json!("-1"),
        json!("9223372036854775808"),
        Value::Null,
    ] {
        assert_eq!(ack(&f, &a, "friend", &invalid).await.0, 400);
    }
    // Reading another account's public data doesn't authorize deleting its subscription.
    assert_eq!(
        req(
            &f,
            "DELETE",
            "/api/v1/subscriptions/friend",
            token(&c),
            Some(json!({"generation":Uuid::new_v4().to_string()})),
            None
        )
        .await
        .0,
        200
    );
    assert_eq!(
        get(&f, "/api/v1/subscriptions/friend", token(&a)).await.0,
        200
    );
    sqlx::query("INSERT INTO rate_windows VALUES($1,$2,120)")
        .bind(format!("notifications:{}", id(&a)))
        .bind(time::OffsetDateTime::now_utc().unix_timestamp() / 60)
        .execute(&f.pool)
        .await
        .unwrap();
    assert_eq!(
        get(&f, "/api/v1/subscriptions/friend/events", token(&a))
            .await
            .0,
        429
    );
}

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
async fn production_migration_v1_upgrade_preserves_accounts_and_rejects_unknown_versions() {
    let Some(f) = fixture().await else { return };
    let a = enroll(&f, "Existing version one account").await;
    let original_checksum: String =
        sqlx::query_scalar("SELECT checksum FROM offtask_migrations WHERE version=1")
            .fetch_one(&f.pool)
            .await
            .unwrap();
    // Restore the synthetic fixture's exact v1 schema, then exercise the additive upgrade.
    sqlx::raw_sql("DROP TABLE mcp_event_outbox,mcp_callback_verifications,mcp_event_subscriptions,oauth_tokens,oauth_codes,oauth_grants,oauth_requests,oauth_link_tickets,notification_subscriptions; DROP INDEX entries_author_id; DELETE FROM offtask_migrations WHERE version>1;")
        .execute(&f.pool).await.unwrap();
    Production::new(f.pool.clone(), "https://offtask.example")
        .await
        .unwrap();
    assert_eq!(get(&f, "/api/v1/me", token(&a)).await.1["id"], id(&a));
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT checksum FROM offtask_migrations WHERE version=1")
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        original_checksum
    );
    assert_eq!(command(&f, "migrate", None).await["schemaVersion"], 4);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM offtask_migrations")
            .fetch_one(&f.pool)
            .await
            .unwrap(),
        4
    );
    sqlx::query("INSERT INTO offtask_migrations VALUES(5,'unknown','test')")
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
async fn production_subscription_generations_reject_stale_ack_delete_and_live_consumer() {
    let Some(f) = fixture().await else { return };
    let a = enroll(&f, "Receiver").await;
    let b = enroll(&f, "First sender").await;
    let c = enroll(&f, "Replacement sender").await;
    let original = subscribe(&f, &a, "replaceable", &[&b], "all").await;
    conversation(&f, &b, None, "generation-original").await;
    let old_page = inbox(&f, &a, "replaceable", 100).await;
    let mut stream = sse(&f, &a, "replaceable", None).await;
    expect_sse(&mut stream, "ready").await;
    assert_eq!(
        unsubscribe(&f, &a, "replaceable", &original["generation"])
            .await
            .0,
        200
    );
    assert_eq!(
        unsubscribe(&f, &a, "replaceable", &original["generation"])
            .await
            .0,
        200
    );
    let replacement = subscribe(&f, &a, "replaceable", &[&c], "all").await;
    assert_ne!(original["generation"], replacement["generation"]);
    conversation(&f, &c, None, "generation-replacement").await;
    let current_page = inbox(&f, &a, "replaceable", 100).await;
    assert!(
        current_page["nextCursor"]
            .as_str()
            .unwrap()
            .parse::<i64>()
            .unwrap()
            > old_page["nextCursor"]
                .as_str()
                .unwrap()
                .parse::<i64>()
                .unwrap()
    );
    assert_eq!(
        ack_generation(
            &f,
            &a,
            "replaceable",
            &old_page["nextCursor"],
            &original["generation"]
        )
        .await
        .0,
        409
    );
    assert_eq!(
        unsubscribe(&f, &a, "replaceable", &original["generation"])
            .await
            .0,
        409
    );
    let current = get(&f, "/api/v1/subscriptions/replaceable", token(&a))
        .await
        .1;
    assert_eq!(current["generation"], replacement["generation"]);
    assert_eq!(current["acknowledgedCursor"], "0");
    let error = expect_sse(&mut stream, "error").await;
    assert!(error.contains("409") || error.contains("404"));
    assert!(stream.chunk().await.unwrap().is_none());
    assert_eq!(
        ack_generation(
            &f,
            &a,
            "replaceable",
            &current_page["nextCursor"],
            &current_page["subscription"]["generation"]
        )
        .await
        .0,
        200
    );
    assert!(
        inbox(&f, &a, "replaceable", 100).await["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        post(
            &f,
            "/api/v1/subscriptions/replaceable/ack",
            token(&a),
            json!({"cursor":"0"}),
            None
        )
        .await
        .0,
        400
    );
    assert_eq!(
        req(
            &f,
            "DELETE",
            "/api/v1/subscriptions/replaceable",
            token(&a),
            Some(json!({})),
            None
        )
        .await
        .0,
        400
    );
}
