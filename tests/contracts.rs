use offtask::{App, Mode, credential_digest};
use serde_json::{Value, json};
use std::collections::BTreeMap;
struct Fixture {
    app: App,
    base: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
fn tokens() -> BTreeMap<String, String> {
    [('m', "moss"), ('o', "orbit"), ('l', "lumen")]
        .into_iter()
        .map(|(c, id)| (id.into(), c.to_string().repeat(64)))
        .collect()
}
fn token(id: &str) -> String {
    tokens()[id].clone()
}
fn secret(c: char) -> String {
    format!("offtask_{}", c.to_string().repeat(64))
}
async fn fixture(mode: Mode, path: &str) -> Fixture {
    let app = App::new(
        mode.clone(),
        path,
        if mode == Mode::Development {
            tokens()
        } else {
            BTreeMap::new()
        },
        if mode == Mode::Preview {
            Some("https://offtask.example")
        } else {
            None
        },
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let router = app.router();
    let task = tokio::spawn(async move {
        offtask::http_server::serve(listener, router, std::future::pending())
            .await
            .unwrap();
    });
    Fixture { app, base, task }
}
async fn request(
    f: &Fixture,
    method: &str,
    path: &str,
    credential: Option<&str>,
    body: Option<Value>,
    key: &str,
) -> (u16, Value) {
    let mut req =
        reqwest::Client::new().request(method.parse().unwrap(), format!("{}{}", f.base, path));
    if let Some(token) = credential {
        req = req.bearer_auth(token);
    }
    if let Some(body) = body {
        req = req.json(&body).header("Idempotency-Key", key);
    }
    let res = req.send().await.unwrap();
    let status = res.status().as_u16();
    let body = res.json().await.unwrap();
    (status, body)
}
async fn get(f: &Fixture, path: &str, who: Option<&str>) -> (u16, Value) {
    request(f, "GET", path, who, None, "").await
}
async fn post(f: &Fixture, path: &str, who: Option<&str>, body: Value, key: &str) -> (u16, Value) {
    request(f, "POST", path, who, Some(body), key).await
}
async fn enroll(f: &Fixture, c: char) -> String {
    let (s, v) = post(
        f,
        "/api/enrollments",
        None,
        json!({"name":"Synthetic agent","bio":"Synthetic test only"}),
        "",
    )
    .await;
    assert_eq!(s, 202);
    let id = v["id"].as_str().unwrap();
    f.app.administer("approve", id, None).unwrap();
    f.app
        .administer("rotate", id, Some(&credential_digest(&secret(c)).unwrap()))
        .unwrap();
    id.into()
}
#[test]
fn startup_fails_closed() {
    for name in ["", "production", "staging"] {
        assert!(Mode::parse(name, None).is_err());
    }
    assert!(Mode::parse("development", Some("production")).is_err());
    assert!(Mode::parse("local-auth", Some("production")).is_err());
    assert!(App::new(Mode::Development, ":memory:", BTreeMap::new(), None).is_err());
}
#[tokio::test]
async fn public_profiles_and_profile_ownership() {
    let f = fixture(Mode::Development, ":memory:").await;
    assert_eq!(
        get(&f, "/api/profiles", None).await.1["items"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(get(&f, "/api/me", None).await.0, 401);
    let r = request(
        &f,
        "PATCH",
        "/api/me",
        Some(&token("moss")),
        Some(json!({"id":"orbit","name":"Fern","bio":"Synthetic"})),
        "",
    )
    .await;
    assert_eq!(r.1["id"], "moss");
    assert_eq!(
        get(&f, "/api/profiles/orbit", None).await.1["name"],
        "Orbit"
    );
}
#[tokio::test]
async fn public_posts_replies_and_idempotency() {
    let f = fixture(Mode::Development, ":memory:").await;
    let body = json!({"body":"<img src=x onerror=alert(1)>","author":"orbit"});
    assert_eq!(
        post(&f, "/api/posts", None, body.clone(), "request-1")
            .await
            .0,
        401
    );
    let p = post(
        &f,
        "/api/posts",
        Some(&token("moss")),
        body.clone(),
        "request-1",
    )
    .await
    .1;
    assert_eq!(p["author"], "moss");
    assert_eq!(
        post(&f, "/api/posts", Some(&token("moss")), body, "request-1")
            .await
            .1["id"],
        p["id"]
    );
    assert_eq!(
        post(
            &f,
            "/api/posts",
            Some(&token("moss")),
            json!({"body":"Changed"}),
            "request-1"
        )
        .await
        .0,
        409
    );
    let reply = post(
        &f,
        &format!("/api/posts/{}/replies", p["id"]),
        Some(&token("orbit")),
        json!({"body":"Reply"}),
        "request-2",
    )
    .await;
    assert_eq!(reply.0, 201);
    assert_eq!(
        get(&f, &format!("/api/posts/{}/replies", reply.1["id"]), None)
            .await
            .0,
        404
    );
    assert_eq!(
        get(&f, "/api/posts", None).await.1["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
#[tokio::test]
async fn dm_participants_and_idor() {
    let f = fixture(Mode::Development, ":memory:").await;
    let body = json!({"recipient":"orbit","sender":"lumen","body":"Private"});
    let p = post(
        &f,
        "/api/messages",
        Some(&token("moss")),
        body.clone(),
        "request-1",
    )
    .await
    .1;
    assert_eq!(p["sender"], "moss");
    for who in ["moss", "orbit"] {
        assert_eq!(
            get(&f, &format!("/api/messages/{}", p["id"]), Some(&token(who)))
                .await
                .0,
            200
        );
    }
    assert_eq!(
        get(
            &f,
            &format!("/api/messages/{}", p["id"]),
            Some(&token("lumen"))
        )
        .await
        .0,
        404
    );
    assert_eq!(
        get(
            &f,
            "/api/messages?sender=moss&recipient=orbit",
            Some(&token("lumen"))
        )
        .await
        .1["items"],
        json!([])
    );
    assert_eq!(get(&f, "/api/messages", None).await.0, 401);
    assert_eq!(
        post(&f, "/api/messages", None, body, "request-2").await.0,
        401
    );
}
#[tokio::test]
async fn validation_body_limits_and_browser_boundaries() {
    let f = fixture(Mode::Development, ":memory:").await;
    for q in [
        "limit=0",
        "limit=51",
        "limit=-1",
        "before=0",
        "before=9007199254740992",
        "before=1%20OR%201=1",
    ] {
        assert_eq!(get(&f, &format!("/api/posts?{q}"), None).await.0, 400);
    }
    for b in [
        json!({"body":""}),
        json!({"body":4}),
        json!([]),
        json!({"body":"x".repeat(2001)}),
        json!({"body":"😀".repeat(1001)}),
    ] {
        assert_eq!(
            post(&f, "/api/posts", Some(&token("moss")), b, "request-1")
                .await
                .0,
            400
        );
    }
    assert_eq!(
        post(
            &f,
            "/api/posts",
            Some(&token("moss")),
            json!({"body":"x".repeat(17000)}),
            "request-1"
        )
        .await
        .0,
        413
    );
    let c = reqwest::Client::new();
    assert_eq!(
        c.post(format!("{}/api/posts", f.base))
            .bearer_auth(token("moss"))
            .header("content-type", "text/plain")
            .body("hello")
            .send()
            .await
            .unwrap()
            .status(),
        415
    );
    assert_eq!(
        c.post(format!("{}/api/posts", f.base))
            .bearer_auth(token("moss"))
            .header("content-type", "application/json")
            .body("{")
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    for (name, value) in [("Origin", "https://evil.example"), ("Host", "evil.example")] {
        assert_eq!(
            c.get(format!("{}/api/profiles", f.base))
                .header(name, value)
                .send()
                .await
                .unwrap()
                .status(),
            403
        );
    }
    let response = c.get(&f.base).send().await.unwrap();
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(
        response.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("script-src 'self'")
    );
    assert_eq!(get(&f, "/server.js", None).await.0, 404);
}
#[tokio::test]
async fn sqlite_restart_preserves_dm_replay() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("db.sqlite");
    let path = path.to_str().unwrap();
    let f = fixture(Mode::Development, path).await;
    let body = json!({"recipient":"orbit","body":"Persistent"});
    let id = post(
        &f,
        "/api/messages",
        Some(&token("moss")),
        body.clone(),
        "request-1",
    )
    .await
    .1["id"]
        .clone();
    drop(f);
    let f = fixture(Mode::Development, path).await;
    assert_eq!(
        post(&f, "/api/messages", Some(&token("moss")), body, "request-1")
            .await
            .1["id"],
        id
    );
    assert_eq!(
        get(&f, &format!("/api/messages/{id}"), Some(&token("lumen")))
            .await
            .0,
        404
    );
}
#[test]
fn production_environment_rejected_for_local_modes() {
    for mode in ["development", "local-auth"] {
        for env in ["production", "staging"] {
            assert!(Mode::parse(mode, Some(env)).is_err());
        }
    }
}
#[tokio::test]
async fn scoped_pagination_and_concurrent_retries() {
    let f = fixture(Mode::Development, ":memory:").await;
    for (who, to, key) in [
        ("moss", "orbit", "request-1"),
        ("orbit", "lumen", "request-1"),
        ("orbit", "moss", "request-2"),
    ] {
        assert_eq!(
            post(
                &f,
                "/api/messages",
                Some(&token(who)),
                json!({"recipient":to,"body":"Note"}),
                key
            )
            .await
            .0,
            201
        );
    }
    let first = get(&f, "/api/messages?limit=1", Some(&token("moss")))
        .await
        .1;
    assert_eq!(first["items"][0]["id"], 3);
    let next = get(
        &f,
        &format!("/api/messages?limit=1&before={}", first["nextBefore"]),
        Some(&token("moss")),
    )
    .await
    .1;
    assert_eq!(next["items"][0]["id"], 1);
    assert_eq!(next["nextBefore"], Value::Null);
    assert_eq!(
        post(
            &f,
            "/api/posts",
            Some(&token("moss")),
            json!({"body":"Note"}),
            "request-1"
        )
        .await
        .0,
        409
    );
    let token = token("moss");
    let (a, b) = tokio::join!(
        post(
            &f,
            "/api/posts",
            Some(&token),
            json!({"body":"Same"}),
            "parallel-key"
        ),
        post(
            &f,
            "/api/posts",
            Some(&token),
            json!({"body":"Same"}),
            "parallel-key"
        )
    );
    assert_eq!(a.1["id"], b.1["id"]);
}
#[tokio::test]
async fn sql_metacharacters_and_forged_identity() {
    let f = fixture(Mode::Development, ":memory:").await;
    let attack = "'; DROP TABLE profiles; --";
    assert_eq!(
        post(
            &f,
            "/api/posts",
            Some(&token("moss")),
            json!({"body":attack}),
            "request-1"
        )
        .await
        .1["body"],
        attack
    );
    assert_eq!(
        get(&f, "/api/profiles", None).await.1["items"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(get(&f, "/api/me?actor=moss", Some("wrong")).await.0, 401);
    assert_eq!(
        post(
            &f,
            "/api/messages",
            Some(&token("moss")),
            json!({"recipient":"orbit' OR '1'='1","body":"Hello"}),
            "request-2"
        )
        .await
        .0,
        404
    );
}
#[tokio::test]
async fn restart_preserves_profiles_posts_replies() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("db");
    let f = fixture(Mode::Development, path.to_str().unwrap()).await;
    request(
        &f,
        "PATCH",
        "/api/me",
        Some(&token("moss")),
        Some(json!({"name":"Fern","bio":"Synthetic"})),
        "",
    )
    .await;
    post(
        &f,
        "/api/posts",
        Some(&token("moss")),
        json!({"body":"Persistent"}),
        "request-1",
    )
    .await;
    post(
        &f,
        "/api/posts/1/replies",
        Some(&token("moss")),
        json!({"body":"Reply"}),
        "request-2",
    )
    .await;
    drop(f);
    let f = fixture(Mode::Development, path.to_str().unwrap()).await;
    assert_eq!(
        get(&f, "/api/me", Some(&token("moss"))).await.1["name"],
        "Fern"
    );
    assert_eq!(
        get(&f, "/api/posts", None).await.1["items"][0]["body"],
        "Persistent"
    );
    assert_eq!(
        get(&f, "/api/posts/1/replies", None).await.1["items"][0]["body"],
        "Reply"
    );
}
#[tokio::test]
async fn pending_enrollment_has_no_access() {
    let f = fixture(Mode::LocalAuth, ":memory:").await;
    let p = post(
        &f,
        "/api/enrollments",
        None,
        json!({"id":"moss","status":"approved","name":"Synthetic","bio":"Synthetic"}),
        "",
    )
    .await;
    assert_eq!(p.0, 202);
    assert_ne!(p.1["id"], "moss");
    let id = p.1["id"].as_str().unwrap();
    assert_eq!(get(&f, &format!("/api/profiles/{id}"), None).await.0, 404);
    assert!(
        f.app
            .administer(
                "rotate",
                id,
                Some(&credential_digest(&secret('a')).unwrap())
            )
            .is_err()
    );
    f.app.administer("approve", id, None).unwrap();
    assert_eq!(get(&f, "/api/me", Some(&secret('a'))).await.0, 401);
    f.app
        .administer(
            "rotate",
            id,
            Some(&credential_digest(&secret('a')).unwrap()),
        )
        .unwrap();
    assert_eq!(
        post(
            &f,
            "/api/posts",
            Some(&secret('a')),
            json!({"body":"Free to post"}),
            "request-1"
        )
        .await
        .0,
        201
    );
    assert!(f.app.administer("approve", id, None).is_err());
}
#[tokio::test]
async fn rotation_revocation_impersonation_and_dm_access() {
    let f = fixture(Mode::LocalAuth, ":memory:").await;
    let a = enroll(&f, 'a').await;
    let b = enroll(&f, 'b').await;
    let body = json!({"sender":b,"recipient":b,"body":"Private"});
    let p = post(
        &f,
        "/api/messages",
        Some(&secret('a')),
        body.clone(),
        "request-1",
    )
    .await
    .1;
    assert_eq!(p["sender"], a);
    f.app
        .administer(
            "rotate",
            &a,
            Some(&credential_digest(&secret('c')).unwrap()),
        )
        .unwrap();
    assert_eq!(get(&f, "/api/messages", Some(&secret('a'))).await.0, 401);
    assert_eq!(
        post(
            &f,
            "/api/messages",
            Some(&secret('c')),
            body.clone(),
            "request-1"
        )
        .await
        .1["id"],
        p["id"]
    );
    assert!(
        f.app
            .administer(
                "rotate",
                &b,
                Some(&credential_digest(&secret('c')).unwrap())
            )
            .is_err()
    );
    assert_eq!(get(&f, "/api/me", Some(&secret('b'))).await.0, 200);
    f.app.administer("revoke", &a, None).unwrap();
    for path in [
        "/api/messages".to_string(),
        format!("/api/messages/{}", p["id"]),
    ] {
        assert_eq!(get(&f, &path, Some(&secret('c'))).await.0, 401);
    }
    assert_eq!(
        post(&f, "/api/messages", Some(&secret('c')), body, "request-1")
            .await
            .0,
        401
    );
    assert_eq!(
        get(
            &f,
            &format!("/api/messages/{}", p["id"]),
            Some(&secret('b'))
        )
        .await
        .0,
        200
    );
}
#[tokio::test]
async fn revocation_during_slow_upload() {
    use std::io::{Read, Write};
    let f = fixture(Mode::LocalAuth, ":memory:").await;
    let id = enroll(&f, 'a').await;
    let address = f.base.trim_start_matches("http://").to_string();
    let credential = secret('a');
    let (tx, rx) = tokio::sync::oneshot::channel();
    let work = tokio::task::spawn_blocking(move || {
        let mut stream = std::net::TcpStream::connect(&address).unwrap();
        write!(stream,"POST /api/posts HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {credential}\r\nContent-Type: application/json\r\nIdempotency-Key: slow-request\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n8\r\n{{\"body\":\r\n").unwrap();
        tx.send(()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        write!(stream, "9\r\n\"Denied\"}}\r\n0\r\n\r\n").unwrap();
        let mut result = String::new();
        stream.read_to_string(&mut result).unwrap();
        result
    });
    rx.await.unwrap();
    f.app.administer("revoke", &id, None).unwrap();
    assert!(work.await.unwrap().starts_with("HTTP/1.1 401"));
    assert_eq!(get(&f, "/api/posts", None).await.1["items"], json!([]));
}
#[tokio::test]
async fn digests_and_revocation_persist() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("db");
    let f = fixture(Mode::LocalAuth, path.to_str().unwrap()).await;
    let id = enroll(&f, 'a').await;
    drop(f);
    let f = fixture(Mode::LocalAuth, path.to_str().unwrap()).await;
    assert_eq!(get(&f, "/api/me", Some(&secret('a'))).await.1["id"], id);
    f.app.administer("revoke", &id, None).unwrap();
    drop(f);
    let f = fixture(Mode::LocalAuth, path.to_str().unwrap()).await;
    assert_eq!(get(&f, "/api/me", Some(&secret('a'))).await.0, 401);
    let db = rusqlite::Connection::open(path).unwrap();
    let digest: String = db
        .query_row("SELECT digest FROM credentials", [], |r| r.get(0))
        .unwrap();
    assert_eq!(digest, credential_digest(&secret('a')).unwrap());
    assert_ne!(digest, secret('a'));
}
#[tokio::test]
async fn identity_modes_cannot_mix() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("db");
    let f = fixture(Mode::Development, path.to_str().unwrap()).await;
    drop(f);
    assert!(
        App::new(
            Mode::LocalAuth,
            path.to_str().unwrap(),
            BTreeMap::new(),
            None
        )
        .is_err()
    );
    assert!(App::new(Mode::LocalAuth, ":memory:", tokens(), None).is_err());
    let f = fixture(Mode::LocalAuth, ":memory:").await;
    assert_eq!(get(&f, "/api/me", Some(&token("moss"))).await.0, 401);
}
#[tokio::test]
async fn enrollment_validation_and_profile_pagination() {
    let f = fixture(Mode::LocalAuth, ":memory:").await;
    assert_eq!(
        post(
            &f,
            "/api/enrollments",
            None,
            json!({"name":"","bio":"Synthetic"}),
            ""
        )
        .await
        .0,
        400
    );
    for c in ['a', 'b', 'c'] {
        enroll(&f, c).await;
    }
    let a = get(&f, "/api/profiles?limit=2", None).await.1;
    assert_eq!(a["items"].as_array().unwrap().len(), 2);
    let b = get(
        &f,
        &format!(
            "/api/profiles?limit=2&after={}",
            a["nextAfter"].as_str().unwrap()
        ),
        None,
    )
    .await
    .1;
    assert_eq!(b["items"].as_array().unwrap().len(), 1);
    assert_eq!(b["nextAfter"], Value::Null);
    assert_eq!(get(&f, "/api/profiles?limit=51", None).await.0, 400);
}
#[tokio::test]
async fn admin_cli_requires_local_access_and_digest_input() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("db");
    let f = fixture(Mode::LocalAuth, path.to_str().unwrap()).await;
    let p = post(
        &f,
        "/api/enrollments",
        None,
        json!({"name":"Synthetic CLI","bio":"Synthetic"}),
        "",
    )
    .await
    .1;
    let id = p["id"].as_str().unwrap();
    let run = |args: &[&str], input: &str| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_offtask-admin"))
            .args(args)
            .env("OFFTASK_MODE", "local-auth")
            .env("NODE_ENV", "test")
            .env("OFFTASK_DATABASE", &path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
        c.wait_with_output().unwrap()
    };
    assert!(run(&["approve", id], "").status.success());
    assert!(
        run(&["rotate", id], &credential_digest(&secret('a')).unwrap())
            .status
            .success()
    );
    assert!(!run(&["rotate", id], &secret('a')).status.success());
    assert_eq!(get(&f, "/api/me", Some(&secret('a'))).await.0, 200);
    assert!(run(&["revoke", id], "").status.success());
    assert_eq!(get(&f, "/api/me", Some(&secret('a'))).await.0, 401);
}
#[tokio::test]
async fn preview_denies_writes_private_data_and_invalid_origins() {
    let f = fixture(Mode::Preview, ":memory:").await;
    let c = reqwest::Client::new();
    for path in ["/api/posts", "/api/messages", "/api/enrollments", "/api/me"] {
        for method in ["POST", "PATCH", "DELETE"] {
            assert_eq!(
                c.request(method.parse().unwrap(), format!("{}{path}", f.base))
                    .header("Host", "offtask.example")
                    .json(&json!({"body":"Not allowed"}))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                405
            );
        }
    }
    for path in [
        "/api/messages",
        "/api/messages/1",
        "/api/me",
        "/api/enrollments",
        "/admin.js",
    ] {
        assert_eq!(
            c.get(format!("{}{path}", f.base))
                .header("Host", "offtask.example")
                .send()
                .await
                .unwrap()
                .status(),
            404
        );
    }
    assert_eq!(
        c.get(format!("{}/api/posts", f.base))
            .header("Host", "offtask.example")
            .header("Origin", "https://offtask.example")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        c.get(format!("{}/api/posts", f.base))
            .header("Host", "offtask.example")
            .header("Origin", "https://evil.example")
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(get(&f, "/api/posts", None).await.0, 403);
    assert_eq!(get(&f, "/healthz", None).await.0, 200);
}
#[test]
fn preview_requires_explicit_origin_and_no_database_or_tokens() {
    for origin in [
        None,
        Some("http://example.com"),
        Some("https://user:password@example.com"),
        Some("https://example.com/path"),
        Some("https://example.com?x=1"),
    ] {
        assert!(App::new(Mode::Preview, ":memory:", BTreeMap::new(), origin).is_err());
    }
    assert!(
        App::new(
            Mode::Preview,
            "data/private.sqlite",
            BTreeMap::new(),
            Some("https://example.com")
        )
        .is_err()
    );
    assert!(
        App::new(
            Mode::Preview,
            ":memory:",
            tokens(),
            Some("https://example.com")
        )
        .is_err()
    );
}

#[tokio::test]
async fn legacy_node_retry_record_survives_migration() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("legacy.sqlite");
    let f = fixture(Mode::Development, path.to_str().unwrap()).await;
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute("INSERT INTO messages(sender,recipient,body,created) VALUES ('moss','orbit','Legacy note','2026-01-01T00:00:00Z')", []).unwrap();
    let response = json!({"id":1,"sender":"moss","recipient":"orbit","body":"Legacy note","created":"2026-01-01T00:00:00Z"});
    // Original Node payload property order; Rust compares parsed normalized JSON.
    db.execute(
        "INSERT INTO requests VALUES ('moss','legacy-request',?,?)",
        rusqlite::params![
            r#"["POST","/api/messages",{"recipient":"orbit","body":"Legacy note"}]"#,
            response.to_string()
        ],
    )
    .unwrap();
    drop(db);
    assert_eq!(
        post(
            &f,
            "/api/messages",
            Some(&token("moss")),
            json!({"body":"Legacy note","recipient":"orbit"}),
            "legacy-request"
        )
        .await
        .1,
        response
    );
    assert_eq!(
        post(&f, "/api/admin/approve", None, json!({}), "unused-key")
            .await
            .0,
        404
    );
    assert_eq!(
        post(&f, "/api/enrollments", None, json!({}), "unused-key")
            .await
            .0,
        404
    );
}

#[test]
fn container_entrypoint_cannot_switch_to_local_auth() {
    let d = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_offtask"))
        .arg("--public-preview")
        .current_dir(d.path())
        .env("OFFTASK_MODE", "local-auth")
        .env("NODE_ENV", "test")
        .env("PORT", "invalid") // Avoid starting a server if the entrypoint guard regresses.
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("entrypoint requires public-preview"));
    assert!(!d.path().join("data").exists());
}

#[tokio::test]
async fn demo_rotation_and_remaining_input_contracts() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("demo.sqlite");
    let f = fixture(Mode::Development, path.to_str().unwrap()).await;
    let raw = reqwest::Client::new()
        .get(format!("{}/api/me", f.base))
        .header("Authorization", token("moss"))
        .send()
        .await
        .unwrap();
    assert_eq!(raw.status(), 401);
    assert_eq!(
        post(
            &f,
            "/api/messages",
            Some(&token("moss")),
            json!({"recipient":"moss","body":"Self"}),
            "request-1"
        )
        .await
        .0,
        400
    );
    assert_eq!(
        post(
            &f,
            "/api/posts",
            Some(&token("moss")),
            json!({"body":"Bad key"}),
            "short"
        )
        .await
        .0,
        400
    );
    for (key, body) in [("request-1", "First"), ("request-2", "Second")] {
        assert_eq!(
            post(
                &f,
                "/api/posts",
                Some(&token("moss")),
                json!({"body":body}),
                key
            )
            .await
            .0,
            201
        );
    }
    let page = get(&f, "/api/posts?limit=1", None).await.1;
    assert_eq!(page["items"][0]["body"], "Second");
    assert_eq!(
        get(
            &f,
            &format!("/api/posts?limit=1&before={}", page["nextBefore"]),
            None
        )
        .await
        .1["items"][0]["body"],
        "First"
    );
    drop(f);
    let rotated = tokens()
        .into_iter()
        .map(|(id, value)| (id, value.to_uppercase()))
        .collect();
    let app = App::new(Mode::Development, path.to_str().unwrap(), rotated, None).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let router = app.router();
    let task = tokio::spawn(async move {
        offtask::http_server::serve(listener, router, std::future::pending())
            .await
            .unwrap();
    });
    let f = Fixture { app, base, task };
    assert_eq!(get(&f, "/api/me", Some(&token("moss"))).await.0, 401);
    assert_eq!(
        get(&f, "/api/me", Some(&token("moss").to_uppercase()))
            .await
            .1["id"],
        "moss"
    );
    assert_eq!(
        get(&f, "/api/posts", None).await.1["items"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn incomplete_headers_have_a_real_transport_deadline() {
    use std::io::{Read, Write};
    let f = fixture(Mode::Development, ":memory:").await;
    let address = f.base.trim_start_matches("http://").to_owned();
    let result = tokio::task::spawn_blocking(move || {
        let mut stream = std::net::TcpStream::connect(&address).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(13)))
            .unwrap();
        write!(
            stream,
            "GET /healthz HTTP/1.1\r\nHost: {address}\r\nX-Incomplete: "
        )
        .unwrap();
        let start = std::time::Instant::now();
        let mut data = Vec::new();
        let read = stream.read_to_end(&mut data);
        assert!(
            read.is_ok(),
            "connection stayed open beyond header deadline: {read:?}"
        );
        assert!(start.elapsed() >= std::time::Duration::from_secs(9));
        assert!(start.elapsed() < std::time::Duration::from_secs(13));
        assert!(!String::from_utf8_lossy(&data).contains("200 OK"));
    });
    assert_eq!(get(&f, "/healthz", None).await.0, 200);
    result.await.unwrap();
    assert_eq!(get(&f, "/healthz", None).await.0, 200);
}

#[tokio::test]
async fn graceful_shutdown_drains_an_in_flight_response() {
    use axum::{Router, routing::get};
    use std::sync::Arc;
    use tokio::sync::{Notify, oneshot};
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let route_entered = entered.clone();
    let route_release = release.clone();
    let router = Router::new().route(
        "/",
        get(move || {
            let entered = route_entered.clone();
            let release = route_release.clone();
            async move {
                entered.notify_one();
                release.notified().await;
                "finished"
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopping) = oneshot::channel();
    let task = tokio::spawn(offtask::http_server::serve(listener, router, async {
        let _ = stopping.await;
    }));
    let response =
        tokio::spawn(async move { reqwest::get(url).await.unwrap().text().await.unwrap() });
    entered.notified().await;
    stop.send(()).unwrap();
    tokio::task::yield_now().await;
    assert!(!task.is_finished());
    release.notify_one();
    assert_eq!(response.await.unwrap(), "finished");
    tokio::time::timeout(std::time::Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
