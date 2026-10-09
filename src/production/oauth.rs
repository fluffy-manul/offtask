//! Opt-in public-client authorization-code OAuth with mandatory S256 PKCE.
//! A short-lived operator-issued ticket selects an existing dot-box. It is never
//! an account access/recovery key. A second, browser-CSRF-bound page asks consent.
//! Raw credentials, request bodies, and authorization URLs must never be logged.
use super::*;
use axum::http::HeaderValue;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::collections::HashSet;
use subtle::ConstantTimeEq;

pub(super) const READ_SCOPE: &str = "offtask:read";
pub(super) const ACK_SCOPE: &str = "offtask:ack";
pub(super) const EVENTS_SCOPE: &str = "offtask:events";
const SCOPES: [&str; 3] = [READ_SCOPE, ACK_SCOPE, EVENTS_SCOPE];
const ACCESS_TTL: i64 = 15 * 60;
const GRANT_TTL: i64 = 30 * 86400;
const REQUEST_TTL: i64 = 10 * 60;
const CODE_TTL: i64 = 60;
const COOKIE: &str = "__Host-offtask_oauth";

type Fields = HashMap<String, String>;

#[derive(Clone)]
pub(super) struct Config {
    pub(super) issuer: String,
    pub(super) resource: String,
    client_id: String,
    redirects: Vec<String>,
}
impl Config {
    /// Browsers apply form-action to the consent form's 303 redirect as well.
    /// Allow only registered callback origins; the actual Location remains
    /// subject to the exact redirect-URI match stored in the request.
    pub(super) fn content_security_policy(&self) -> String {
        let mut origins = self
            .redirects
            .iter()
            .map(|redirect| {
                Url::parse(redirect)
                    .expect("validated OAuth redirect URI")
                    .origin()
                    .ascii_serialization()
            })
            .collect::<Vec<_>>();
        origins.sort();
        origins.dedup();
        format!(
            "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self' {}",
            origins.join(" ")
        )
    }
    pub(super) fn new(origin: &Url, client_id: &str, redirects: Vec<String>) -> Result<Self> {
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
            || client_id.is_empty()
            || client_id.len() > 256
            || !client_id.bytes().all(|b| b.is_ascii_graphic())
            || redirects.is_empty()
            || redirects.len() > 8
        {
            return Err(err(400, "Invalid OAuth configuration"));
        }
        let mut seen = HashSet::new();
        for redirect in &redirects {
            let parsed =
                Url::parse(redirect).map_err(|_| err(400, "Invalid OAuth redirect URI"))?;
            if redirect.len() > 2048
                || parsed.scheme() != "https"
                || parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.fragment().is_some()
                || parsed.as_str() != redirect
                || parsed.query_pairs().any(|(k, _)| {
                    matches!(k.as_ref(), "code" | "error" | "state" | "iss" | "resource")
                })
                || !seen.insert(redirect)
            {
                return Err(err(
                    400,
                    "OAuth redirect URIs must be unique exact canonical HTTPS URLs without fragments or reserved response parameters",
                ));
            }
        }
        let issuer = origin.origin().ascii_serialization();
        Ok(Self {
            resource: format!("{issuer}/mcp"),
            issuer,
            client_id: client_id.into(),
            redirects,
        })
    }
    pub(super) fn from_env(origin: &Url) -> Result<Option<Self>> {
        match env::var("OFFTASK_OAUTH_ENABLED").as_deref() {
            Err(env::VarError::NotPresent) | Ok("false") => return Ok(None),
            Ok("true") => {}
            _ => return Err(err(400, "OFFTASK_OAUTH_ENABLED must be true or false")),
        }
        let client = env::var("OFFTASK_OAUTH_CLIENT_ID")
            .map_err(|_| err(400, "OFFTASK_OAUTH_CLIENT_ID is required"))?;
        let redirects = env::var("OFFTASK_OAUTH_REDIRECT_URIS")
            .map_err(|_| err(400, "OFFTASK_OAUTH_REDIRECT_URIS is required"))?
            .split(',')
            .map(str::to_string)
            .collect();
        Self::new(origin, &client, redirects).map(Some)
    }
    fn binds(&self, row: &sqlx::postgres::PgRow) -> bool {
        row.get::<String, _>("issuer") == self.issuer
            && row.get::<String, _>("resource") == self.resource
            && row.get::<String, _>("client_id") == self.client_id
            && self
                .redirects
                .contains(&row.get::<String, _>("redirect_uri"))
    }
}
fn config(app: &Production) -> Result<&Config> {
    app.oauth
        .as_deref()
        .ok_or_else(|| err(404, "OAuth is not enabled"))
}

pub(super) fn handles(path: &str) -> bool {
    matches!(
        path,
        "/.well-known/oauth-protected-resource"
            | "/.well-known/oauth-protected-resource/mcp"
            | "/.well-known/oauth-authorization-server"
            | "/oauth/authorize"
            | "/oauth/consent"
            | "/oauth/token"
            | "/oauth/revoke"
    )
}
pub(super) fn challenge(app: &Production, scope: &str) -> String {
    // All interpolation comes from validated origin and our fixed scope allowlist.
    let issuer = app.origin.origin().ascii_serialization();
    let scope = if SCOPES.contains(&scope) {
        scope
    } else {
        READ_SCOPE
    };
    format!(
        "Bearer resource_metadata=\"{issuer}/.well-known/oauth-protected-resource/mcp\", scope=\"{scope}\", error=\"invalid_token\", error_description=\"Sign in to the selected Offtask dot-box\""
    )
}
fn fields(value: &str, allowed: &[&str]) -> Result<Fields> {
    if value.len() > 8192 {
        return Err(err(400, "invalid_request"));
    }
    let mut result = Fields::new();
    for (k, v) in url::form_urlencoded::parse(value.as_bytes()) {
        if !allowed.contains(&k.as_ref()) || result.insert(k.into_owned(), v.into_owned()).is_some()
        {
            return Err(err(400, "invalid_request"));
        }
    }
    Ok(result)
}
fn required<'a>(fields: &'a Fields, name: &str) -> Result<&'a str> {
    fields
        .get(name)
        .map(String::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| err(400, "invalid_request"))
}
fn scopes(input: &str) -> Result<Vec<String>> {
    let mut result = Vec::new();
    for part in input.split(' ') {
        if !SCOPES.contains(&part) || result.iter().any(|p| p == part) {
            return Err(err(400, "invalid_scope"));
        }
        result.push(part.to_string());
    }
    if result.is_empty() {
        return Err(err(400, "invalid_scope"));
    }
    result.sort();
    Ok(result)
}
fn pkce_challenge(verifier: &str) -> Result<String> {
    if !(43..=128).contains(&verifier.len())
        || !verifier
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(err(400, "invalid_grant"));
    }
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())))
}
fn valid_challenge(value: &str) -> bool {
    value.len() == 43
        && URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|bytes| bytes.len() == 32)
}
fn eq_secret(left: &str, right: &str) -> bool {
    bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}
fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn html(content: String) -> Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], format!("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Connect an Offtask dot-box</title></head><body><main>{content}</main></body></html>")).into_response()
}
fn request_inputs(id: &str, csrf: &str) -> String {
    format!(
        "<input type=\"hidden\" name=\"request\" value=\"{}\"><input type=\"hidden\" name=\"csrf\" value=\"{}\">",
        html_escape(id),
        html_escape(csrf)
    )
}
fn browser(headers: &HeaderMap) -> Result<String> {
    let mut found = None;
    for raw in headers.get_all(header::COOKIE) {
        let raw = raw.to_str().map_err(|_| err(400, "invalid_request"))?;
        for part in raw.split(';') {
            if let Some((name, value)) = part.trim().split_once('=')
                && name == COOKIE
            {
                if found.is_some() {
                    return Err(err(400, "invalid_request"));
                }
                found = Some(
                    secret_digest(value, "ot_browser_").map_err(|_| err(400, "invalid_request"))?,
                );
            }
        }
    }
    found.ok_or_else(|| err(400, "invalid_request"))
}
fn browser_origin(config: &Config, headers: &HeaderMap) -> Result<()> {
    // Browser form posts always supply Origin; a missing or duplicate origin is not trusted.
    if headers.get_all(header::ORIGIN).iter().count() != 1
        || headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) != Some(&config.issuer)
    {
        return Err(err(403, "invalid_request"));
    }
    Ok(())
}
async fn request_tx(
    tx: &mut Tx<'_>,
    cfg: &Config,
    headers: &HeaderMap,
    form: &Fields,
) -> Result<sqlx::postgres::PgRow> {
    browser_origin(cfg, headers)?;
    let hash = secret_digest(required(form, "request")?, "ot_request_")
        .map_err(|_| err(400, "invalid_request"))?;
    let csrf = secret_digest(required(form, "csrf")?, "ot_csrf_")
        .map_err(|_| err(400, "invalid_request"))?;
    let browser = browser(headers)?;
    let row = sqlx::query(
        "SELECT * FROM oauth_requests WHERE digest=$1 AND expires>$2 AND NOT used FOR UPDATE",
    )
    .bind(hash)
    .bind(unix())
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)?
    .ok_or_else(|| err(400, "invalid_request"))?;
    if !cfg.binds(&row)
        || !eq_secret(&row.get::<String, _>("csrf_digest"), &csrf)
        || !eq_secret(&row.get::<String, _>("browser_digest"), &browser)
    {
        return Err(err(400, "invalid_request"));
    }
    Ok(row)
}
async fn authorize(app: &Production, query: &str) -> Result<Response> {
    let cfg = config(app)?;
    let f = fields(
        query,
        &[
            "response_type",
            "client_id",
            "redirect_uri",
            "scope",
            "state",
            "resource",
            "code_challenge",
            "code_challenge_method",
        ],
    )?;
    if required(&f, "client_id")? != cfg.client_id {
        return Err(err(400, "invalid_client"));
    }
    if !cfg
        .redirects
        .iter()
        .any(|v| Some(v.as_str()) == f.get("redirect_uri").map(String::as_str))
    {
        return Err(err(400, "invalid_request"));
    }
    if required(&f, "response_type")? != "code" {
        return Err(err(400, "unsupported_response_type"));
    }
    if required(&f, "resource")? != cfg.resource {
        return Err(err(400, "invalid_target"));
    }
    if required(&f, "code_challenge_method")? != "S256"
        || !valid_challenge(required(&f, "code_challenge")?)
    {
        return Err(err(400, "invalid_request"));
    }
    let state = required(&f, "state")?;
    if state.len() > 1024 || state.chars().any(char::is_control) {
        return Err(err(400, "invalid_request"));
    }
    let granted = scopes(required(&f, "scope")?)?;
    let id = secret("ot_request_");
    let csrf = secret("ot_csrf_");
    let browser = secret("ot_browser_");
    let mut tx = write_tx(&app.pool).await?;
    sqlx::query("DELETE FROM oauth_requests WHERE expires<=$1")
        .bind(unix())
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    sqlx::query("INSERT INTO oauth_requests(digest,browser_digest,csrf_digest,issuer,resource,client_id,redirect_uri,scopes,state,code_challenge,expires) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
        .bind(digest(&id)).bind(digest(&browser)).bind(digest(&csrf)).bind(&cfg.issuer).bind(&cfg.resource).bind(&cfg.client_id)
        .bind(required(&f,"redirect_uri")?).bind(granted).bind(state).bind(required(&f,"code_challenge")?).bind(unix()+REQUEST_TTL)
        .execute(&mut *tx).await.map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;
    let mut response = html(format!(
        "<h1>Choose your Offtask dot-box</h1><p>Client: {}</p><p>Enter the one-time link ticket from your Offtask operator. Never enter an access or recovery key here. You will review the box and permissions before connecting.</p><form method=\"post\" action=\"/oauth/authorize\">{}<label>One-time link ticket <input name=\"ticket\" type=\"password\" required maxlength=\"80\" autocomplete=\"off\"></label><button type=\"submit\">Review connection</button></form>",
        html_escape(&cfg.client_id),
        request_inputs(&id, &csrf)
    ));
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{COOKIE}={browser}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={REQUEST_TTL}"
        ))
        .map_err(|_| err(500, "Invalid cookie"))?,
    );
    Ok(response)
}
async fn select_box(app: &Production, headers: &HeaderMap, form: &Fields) -> Result<Response> {
    let cfg = config(app)?;
    let mut tx = write_tx(&app.pool).await?;
    let request = request_tx(&mut tx, cfg, headers, form).await?;
    if request.get::<Option<String>, _>("account").is_some() {
        return Err(err(400, "invalid_request"));
    }
    let ticket = secret_digest(required(form, "ticket")?, "offtask_link_")
        .map_err(|_| err(400, "invalid_grant"))?;
    let row=sqlx::query("UPDATE oauth_link_tickets t SET used=TRUE FROM accounts a WHERE t.digest=$1 AND t.expires>$2 AND NOT t.used AND t.issuer=$3 AND t.resource=$4 AND t.client_id=$5 AND a.id=t.account AND NOT a.disabled RETURNING a.id,a.name")
        .bind(ticket).bind(unix()).bind(&cfg.issuer).bind(&cfg.resource).bind(&cfg.client_id).fetch_optional(&mut *tx).await.map_err(db_error)?.ok_or_else(||err(400,"invalid_grant"))?;
    let account: String = row.get("id");
    sqlx::query("UPDATE oauth_requests SET account=$2 WHERE digest=$1")
        .bind(request.get::<String, _>("digest"))
        .bind(&account)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;
    let permissions=request.get::<Vec<String>,_>("scopes").iter().map(|scope|match scope.as_str(){READ_SCOPE=>"Read this dot-box's profile, subscriptions, authorized inbox entries and conversations",ACK_SCOPE=>"Acknowledge delivered inbox entries",EVENTS_SCOPE=>"Subscribe to notifications and deliver authorized inbox events to the configured ChatGPT callback service",_=>"Unknown permission"}).map(|v|format!("<li>{}</li>",html_escape(v))).collect::<String>();
    Ok(html(format!(
        "<h1>Connect this dot-box?</h1><p>Dot-box: <strong>{}</strong></p><p>Box ID: {}</p><p>Client: {}</p><p>Resource: {}</p><p>The connection lasts up to 30 days unless revoked sooner. It authenticates this selected Offtask box, not a particular dot instance.</p><ul>{permissions}</ul><form method=\"post\" action=\"/oauth/consent\">{}<button type=\"submit\" name=\"decision\" value=\"approve\">Connect this dot-box</button><button type=\"submit\" name=\"decision\" value=\"deny\">Cancel</button></form>",
        html_escape(&row.get::<String, _>("name")),
        html_escape(&account),
        html_escape(&cfg.client_id),
        html_escape(&cfg.resource),
        request_inputs(required(form, "request")?, required(form, "csrf")?)
    )))
}
async fn consent(app: &Production, headers: &HeaderMap, form: &Fields) -> Result<Response> {
    let cfg = config(app)?;
    let decision = required(form, "decision")?;
    if !matches!(decision, "approve" | "deny") {
        return Err(err(400, "invalid_request"));
    }
    let mut tx = write_tx(&app.pool).await?;
    let request = request_tx(&mut tx, cfg, headers, form).await?;
    let account = request
        .get::<Option<String>, _>("account")
        .ok_or_else(|| err(400, "invalid_request"))?;
    let enabled: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM accounts WHERE id=$1 AND NOT disabled)")
            .bind(&account)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_error)?;
    if !enabled {
        return Err(err(400, "invalid_grant"));
    }
    sqlx::query("UPDATE oauth_requests SET used=TRUE WHERE digest=$1")
        .bind(request.get::<String, _>("digest"))
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    let mut destination = Url::parse(&request.get::<String, _>("redirect_uri"))
        .map_err(|_| err(500, "Invalid stored redirect"))?;
    if decision == "approve" {
        let grant = Uuid::new_v4().to_string();
        let code = secret("ot_code_");
        sqlx::query("INSERT INTO oauth_grants(id,account,issuer,resource,client_id,redirect_uri,scopes,expires,created) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind(&grant).bind(&account).bind(&cfg.issuer).bind(&cfg.resource).bind(&cfg.client_id).bind(request.get::<String,_>("redirect_uri")).bind(request.get::<Vec<String>,_>("scopes")).bind(unix()+GRANT_TTL).bind(now()).execute(&mut *tx).await.map_err(db_error)?;
        sqlx::query(
            "INSERT INTO oauth_codes(digest,grant_id,code_challenge,expires) VALUES($1,$2,$3,$4)",
        )
        .bind(digest(&code))
        .bind(&grant)
        .bind(request.get::<String, _>("code_challenge"))
        .bind(unix() + CODE_TTL)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        audit(&mut tx, "oauth-grant", &grant).await?;
        destination.query_pairs_mut().append_pair("code", &code);
    } else {
        destination
            .query_pairs_mut()
            .append_pair("error", "access_denied");
    }
    destination
        .query_pairs_mut()
        .append_pair("state", &request.get::<String, _>("state"))
        .append_pair("iss", &cfg.issuer)
        .append_pair("resource", &cfg.resource);
    tx.commit().await.map_err(db_error)?;
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(destination.as_str()).map_err(|_| err(500, "Invalid redirect"))?,
    );
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "__Host-offtask_oauth=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0",
        ),
    );
    Ok(response)
}

#[derive(Debug)]
pub(super) struct Grant {
    pub(super) id: String,
    pub(super) account: String,
}
fn check_grant(cfg: &Config, row: &sqlx::postgres::PgRow, scope: &str) -> Result<Grant> {
    if !cfg.binds(row)
        || row.get::<bool, _>("revoked")
        || row.get::<bool, _>("disabled")
        || row.get::<i64, _>("expires") <= unix()
    {
        return Err(err(401, "invalid_token"));
    }
    if !scope.is_empty()
        && !row
            .get::<Vec<String>, _>("scopes")
            .iter()
            .any(|s| s == scope)
    {
        return Err(err(403, "insufficient_scope"));
    }
    Ok(Grant {
        id: row.get("id"),
        account: row.get("account"),
    })
}
pub(super) async fn grant_tx(
    app: &Production,
    tx: &mut Tx<'_>,
    id: &str,
    required_scope: &str,
) -> Result<Grant> {
    let cfg = config(app)?;
    let row = sqlx::query(
        "SELECT g.*,a.disabled FROM oauth_grants g JOIN accounts a ON a.id=g.account WHERE g.id=$1",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)?
    .ok_or_else(|| err(401, "invalid_token"))?;
    check_grant(cfg, &row, required_scope)
}
pub(super) async fn actor_tx(
    app: &Production,
    tx: &mut Tx<'_>,
    headers: &HeaderMap,
    required_scope: &str,
) -> Result<Grant> {
    let cfg = config(app)?;
    if headers.get_all(header::AUTHORIZATION).iter().count() != 1 {
        return Err(err(401, "invalid_token"));
    }
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| err(401, "invalid_token"))?;
    let hash = secret_digest(token, "ot_access_").map_err(|_| err(401, "invalid_token"))?;
    let row=sqlx::query("SELECT g.*,a.disabled FROM oauth_tokens t JOIN oauth_grants g ON g.id=t.grant_id JOIN accounts a ON a.id=g.account WHERE t.digest=$1 AND t.kind='access' AND NOT t.used AND t.expires>$2").bind(hash).bind(unix()).fetch_optional(&mut **tx).await.map_err(db_error)?.ok_or_else(||err(401,"invalid_token"))?;
    check_grant(cfg, &row, required_scope)
}
pub(super) async fn revoke_grant_tx(tx: &mut Tx<'_>, id: &str) -> Result<()> {
    sqlx::query("UPDATE oauth_grants SET revoked=TRUE WHERE id=$1")
        .bind(id)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
    super::mcp_events::cancel_grant_tx(tx, id).await?;
    audit(tx, "oauth-revoke", id).await
}
pub(super) async fn revoke_account_tx(tx: &mut Tx<'_>, account: &str) -> Result<()> {
    let ids = sqlx::query_scalar::<_, String>(
        "SELECT id FROM oauth_grants WHERE account=$1 AND NOT revoked",
    )
    .bind(account)
    .fetch_all(&mut **tx)
    .await
    .map_err(db_error)?;
    for id in ids {
        revoke_grant_tx(tx, &id).await?;
    }
    sqlx::query("UPDATE oauth_link_tickets SET used=TRUE WHERE account=$1")
        .bind(account)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
    sqlx::query("UPDATE oauth_requests SET used=TRUE WHERE account=$1")
        .bind(account)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
    Ok(())
}
async fn issue_tokens(
    tx: &mut Tx<'_>,
    grant: &str,
    expires: i64,
    scope: &[String],
) -> Result<Value> {
    let issued = unix();
    if expires <= issued {
        return Err(err(400, "invalid_grant"));
    }
    let access = secret("ot_access_");
    let refresh = secret("ot_refresh_");
    let access_expires = (issued + ACCESS_TTL).min(expires);
    for (token, kind, expiry) in [
        (&access, "access", access_expires),
        (&refresh, "refresh", expires),
    ] {
        sqlx::query("INSERT INTO oauth_tokens(digest,grant_id,kind,expires) VALUES($1,$2,$3,$4)")
            .bind(digest(token))
            .bind(grant)
            .bind(kind)
            .bind(expiry)
            .execute(&mut **tx)
            .await
            .map_err(db_error)?;
    }
    Ok(
        json!({"access_token":access,"token_type":"Bearer","expires_in":access_expires-issued,"refresh_token":refresh,"scope":scope.join(" ")}),
    )
}
async fn exchange(app: &Production, form: &Fields) -> Result<Value> {
    let cfg = config(app)?;
    if required(form, "client_id")? != cfg.client_id {
        return Err(err(400, "invalid_client"));
    }
    if required(form, "resource")? != cfg.resource {
        return Err(err(400, "invalid_target"));
    }
    let grant_type = required(form, "grant_type")?;
    let mut tx = write_tx(&app.pool).await?;
    let (row, token_hash, is_code) = match grant_type {
        "authorization_code" => {
            if form.contains_key("refresh_token") || form.contains_key("scope") {
                return Err(err(400, "invalid_request"));
            }
            let hash = secret_digest(required(form, "code")?, "ot_code_")
                .map_err(|_| err(400, "invalid_grant"))?;
            let row=sqlx::query("SELECT g.*,a.disabled,c.used AS token_used,c.expires AS token_expires,c.code_challenge FROM oauth_codes c JOIN oauth_grants g ON g.id=c.grant_id JOIN accounts a ON a.id=g.account WHERE c.digest=$1 FOR UPDATE OF c,g")
                .bind(&hash).fetch_optional(&mut *tx).await.map_err(db_error)?.ok_or_else(||err(400,"invalid_grant"))?;
            if required(form, "redirect_uri")? != row.get::<String, _>("redirect_uri")
                || !eq_secret(
                    &pkce_challenge(required(form, "code_verifier")?)?,
                    &row.get::<String, _>("code_challenge"),
                )
            {
                return Err(err(400, "invalid_grant"));
            }
            (row, hash, true)
        }
        "refresh_token" => {
            if ["code", "code_verifier", "redirect_uri"]
                .iter()
                .any(|k| form.contains_key(*k))
            {
                return Err(err(400, "invalid_request"));
            }
            let hash = secret_digest(required(form, "refresh_token")?, "ot_refresh_")
                .map_err(|_| err(400, "invalid_grant"))?;
            let row=sqlx::query("SELECT g.*,a.disabled,t.used AS token_used,t.expires AS token_expires FROM oauth_tokens t JOIN oauth_grants g ON g.id=t.grant_id JOIN accounts a ON a.id=g.account WHERE t.digest=$1 AND t.kind='refresh' FOR UPDATE OF t,g")
                .bind(&hash).fetch_optional(&mut *tx).await.map_err(db_error)?.ok_or_else(||err(400,"invalid_grant"))?;
            // Scope narrowing is not offered: refresh preserves the explicitly consented grant.
            if let Some(requested) = form.get("scope")
                && scopes(requested)? != row.get::<Vec<String>, _>("scopes")
            {
                return Err(err(400, "invalid_scope"));
            }
            (row, hash, false)
        }
        _ => return Err(err(400, "unsupported_grant_type")),
    };
    check_grant(cfg, &row, "").map_err(|_| err(400, "invalid_grant"))?;
    if row.get::<bool, _>("token_used") {
        revoke_grant_tx(&mut tx, &row.get::<String, _>("id")).await?;
        // Replay revocation must survive the error response.
        tx.commit().await.map_err(db_error)?;
        return Err(err(400, "invalid_grant"));
    }
    if row.get::<i64, _>("token_expires") <= unix() {
        return Err(err(400, "invalid_grant"));
    }
    sqlx::query(if is_code {
        "UPDATE oauth_codes SET used=TRUE WHERE digest=$1"
    } else {
        "UPDATE oauth_tokens SET used=TRUE WHERE digest=$1"
    })
    .bind(token_hash)
    .execute(&mut *tx)
    .await
    .map_err(db_error)?;
    let tokens = issue_tokens(
        &mut tx,
        &row.get::<String, _>("id"),
        row.get("expires"),
        &row.get::<Vec<String>, _>("scopes"),
    )
    .await?;
    tx.commit().await.map_err(db_error)?;
    Ok(tokens)
}
async fn revoke(app: &Production, form: &Fields) -> Result<Value> {
    let cfg = config(app)?;
    if required(form, "client_id")? != cfg.client_id {
        return Err(err(400, "invalid_client"));
    }
    if let Some(hint) = form.get("token_type_hint")
        && !matches!(hint.as_str(), "access_token" | "refresh_token")
    {
        return Err(err(400, "unsupported_token_type"));
    }
    let token = required(form, "token")?;
    let prefix = if token.starts_with("ot_access_") {
        "ot_access_"
    } else {
        "ot_refresh_"
    };
    // RFC 7009: unknown or already revoked tokens return success, without disclosure.
    let Ok(hash) = secret_digest(token, prefix) else {
        return Ok(json!({}));
    };
    let mut tx = write_tx(&app.pool).await?;
    let id=sqlx::query_scalar::<_,String>("SELECT g.id FROM oauth_tokens t JOIN oauth_grants g ON g.id=t.grant_id WHERE t.digest=$1 AND g.client_id=$2 AND g.issuer=$3 AND g.resource=$4")
        .bind(hash).bind(&cfg.client_id).bind(&cfg.issuer).bind(&cfg.resource).fetch_optional(&mut *tx).await.map_err(db_error)?;
    if let Some(id) = id {
        revoke_grant_tx(&mut tx, &id).await?;
    }
    tx.commit().await.map_err(db_error)?;
    Ok(json!({}))
}
/// The CLI is an operator capability. Capture the ticket once in secure stdout;
/// never emit it to platform logs or place it in a browser URL.
pub(super) async fn issue_link_ticket(pool: &PgPool, cfg: &Config, account: &str) -> Result<Value> {
    uuid(account)?;
    let mut tx = write_tx(pool).await?;
    let enabled: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM accounts WHERE id=$1 AND NOT disabled)")
            .bind(account)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_error)?;
    if !enabled {
        return Err(err(404, "Enabled dot-box not found"));
    }
    sqlx::query("UPDATE oauth_link_tickets SET used=TRUE WHERE account=$1 AND NOT used")
        .bind(account)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    let ticket = secret("offtask_link_");
    let expires = unix() + REQUEST_TTL;
    sqlx::query("INSERT INTO oauth_link_tickets(digest,account,issuer,resource,client_id,expires,created) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(digest(&ticket)).bind(account).bind(&cfg.issuer).bind(&cfg.resource).bind(&cfg.client_id).bind(expires).bind(now()).execute(&mut *tx).await.map_err(db_error)?;
    audit(&mut tx, "oauth-link-ticket", account).await?;
    tx.commit().await.map_err(db_error)?;
    Ok(
        json!({"account":account,"linkTicket":ticket,"expiresAt":expires,"clientId":cfg.client_id,"resource":cfg.resource,"delivery":"shown-once; enter only in the Offtask HTTPS consent form; never in URLs, tools, or logs"}),
    )
}
pub(super) async fn handle(app: &Production, req: Request) -> Result<Response> {
    let cfg = config(app)?;
    let path = req.uri().path();
    if req.method() == "GET" {
        if path.starts_with("/.well-known/") {
            if req.uri().query().is_some() {
                return Err(err(400, "invalid_request"));
            }
            let value = if path == "/.well-known/oauth-authorization-server" {
                json!({"issuer":cfg.issuer,"authorization_endpoint":format!("{}/oauth/authorize",cfg.issuer),"token_endpoint":format!("{}/oauth/token",cfg.issuer),"revocation_endpoint":format!("{}/oauth/revoke",cfg.issuer),"response_types_supported":["code"],"grant_types_supported":["authorization_code","refresh_token"],"token_endpoint_auth_methods_supported":["none"],"revocation_endpoint_auth_methods_supported":["none"],"code_challenge_methods_supported":["S256"],"scopes_supported":SCOPES,"authorization_response_iss_parameter_supported":true})
            } else {
                json!({"resource":cfg.resource,"authorization_servers":[cfg.issuer],"scopes_supported":SCOPES,"bearer_methods_supported":["header"],"resource_name":"Offtask dot-box"})
            };
            return Ok(axum::Json(value).into_response());
        }
        if path == "/oauth/authorize" {
            app.rate("oauth-authorize", 60)?;
            return authorize(app, req.uri().query().unwrap_or("")).await;
        }
        return Err(err(405, "Use POST"));
    }
    if req.method() != "POST" || !path.starts_with("/oauth/") {
        return Err(err(405, "Use GET or POST"));
    }
    if req.uri().query().is_some() {
        return Err(err(400, "invalid_request"));
    }
    app.rate("oauth-post", 120)?;
    let headers = req.headers().clone();
    if headers.contains_key(header::AUTHORIZATION) {
        return Err(err(400, "invalid_client"));
    }
    if headers.get_all(header::CONTENT_TYPE).iter().count() != 1
        || headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .map(str::trim)
            != Some("application/x-www-form-urlencoded")
    {
        return Err(err(415, "Use application/x-www-form-urlencoded"));
    }
    let path = path.to_string();
    let bytes = tokio::time::timeout(Duration::from_secs(15), to_bytes(req.into_body(), 8192))
        .await
        .map_err(|_| err(408, "Request body timed out"))?
        .map_err(|_| err(413, "Request body too large"))?;
    let body = std::str::from_utf8(&bytes).map_err(|_| err(400, "invalid_request"))?;
    match path.as_str() {
        "/oauth/authorize" => {
            select_box(
                app,
                &headers,
                &fields(body, &["request", "csrf", "ticket"])?,
            )
            .await
        }
        "/oauth/consent" => {
            consent(
                app,
                &headers,
                &fields(body, &["request", "csrf", "decision"])?,
            )
            .await
        }
        "/oauth/token" => {
            let tokens = exchange(
                app,
                &fields(
                    body,
                    &[
                        "grant_type",
                        "client_id",
                        "resource",
                        "code",
                        "redirect_uri",
                        "code_verifier",
                        "refresh_token",
                        "scope",
                    ],
                )?,
            )
            .await?;
            let mut response = axum::Json(tokens).into_response();
            response
                .headers_mut()
                .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
            Ok(response)
        }
        "/oauth/revoke" => Ok(axum::Json(
            revoke(
                app,
                &fields(body, &["token", "token_type_hint", "client_id"])?,
            )
            .await?,
        )
        .into_response()),
        _ => Err(err(404, "Route not found")),
    }
}

#[cfg(test)]
pub(super) async fn test_grant(
    app: &Production,
    account: &str,
    requested_scopes: &str,
) -> (Grant, String) {
    let cfg = config(app).unwrap();
    let id = Uuid::new_v4().to_string();
    let granted = scopes(requested_scopes).unwrap();
    let mut tx = write_tx(&app.pool).await.unwrap();
    sqlx::query("INSERT INTO oauth_grants(id,account,issuer,resource,client_id,redirect_uri,scopes,expires,created) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(&id).bind(account).bind(&cfg.issuer).bind(&cfg.resource).bind(&cfg.client_id).bind(&cfg.redirects[0]).bind(&granted).bind(unix()+GRANT_TTL).bind(now()).execute(&mut *tx).await.unwrap();
    let tokens = issue_tokens(&mut tx, &id, unix() + GRANT_TTL, &granted)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    (
        Grant {
            id,
            account: account.into(),
        },
        tokens["access_token"].as_str().unwrap().into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn cfg() -> Config {
        Config::new(
            &Url::parse("https://offtask.example").unwrap(),
            "synthetic-client",
            vec!["https://chatgpt.example/oauth/callback".into()],
        )
        .unwrap()
    }
    #[test]
    fn oauth_pkce_is_rfc7636_s256_with_strict_verifier() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").unwrap(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        for input in [
            "a".repeat(42),
            "a".repeat(129),
            "/".repeat(43),
            "é".repeat(43),
        ] {
            assert!(pkce_challenge(&input).is_err());
        }
        for n in [43, 128] {
            assert!(pkce_challenge(&"a".repeat(n)).is_ok());
        }
        assert!(!valid_challenge(&"a".repeat(42)));
        assert!(!valid_challenge(&"!".repeat(43)));
        assert!(!valid_challenge(&format!("{}=", "a".repeat(43))));
    }
    #[test]
    fn oauth_config_exact_redirects_and_form_fields() {
        let origin = Url::parse("https://offtask.example").unwrap();
        for redirect in [
            "http://chatgpt.example/cb",
            "https://user@chatgpt.example/cb",
            "https://chatgpt.example/cb#fragment",
            "https://CHATGPT.example/cb",
            "https://chatgpt.example/cb?code=x",
        ] {
            assert!(
                Config::new(&origin, "client", vec![redirect.into()]).is_err(),
                "{redirect}"
            );
        }
        assert!(
            Config::new(
                &origin,
                "client",
                vec!["https://chatgpt.example/cb".into(); 2]
            )
            .is_err()
        );
        assert!(fields("client_id=x&client_id=y", &["client_id"]).is_err());
        assert!(fields("client_secret=x", &["client_id"]).is_err());
        assert!(scopes("offtask:read offtask:read").is_err());
        assert!(scopes("offtask:write").is_err());
        assert!(scopes("offtask:read  offtask:ack").is_err());
        assert!(scopes("").is_err());
        assert_eq!(
            scopes("offtask:read offtask:ack").unwrap(),
            vec!["offtask:ack", "offtask:read"]
        );
        assert_eq!(html_escape("<a\"&'>"), "&lt;a&quot;&amp;&#39;&gt;");
    }
    #[test]
    fn oauth_consent_csp_allows_only_registered_origins() {
        let cfg = Config::new(
            &Url::parse("https://offtask.example").unwrap(),
            "client",
            vec![
                "https://callback.example/cb".into(),
                "https://callback.example/other?label=%27unsafe-inline%27".into(),
                "https://second.example:8443/cb".into(),
            ],
        )
        .unwrap();
        let csp = cfg.content_security_policy();
        assert!(
            csp.ends_with(
                "form-action 'self' https://callback.example https://second.example:8443"
            )
        );
        assert!(!csp.contains("unsafe-inline"));
        assert!(!csp.contains("/cb"));
        assert!(!csp.contains("*"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(
            Config::new(
                &Url::parse("https://offtask.example").unwrap(),
                "client",
                vec!["https://callback.example/\n;script-src *".into()]
            )
            .is_err()
        );
    }
    #[test]
    fn oauth_browser_checks_are_exact() {
        let cfg = cfg();
        let mut headers = HeaderMap::new();
        assert!(browser_origin(&cfg, &headers).is_err());
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://offtask.example"),
        );
        assert!(browser_origin(&cfg, &headers).is_ok());
        headers.append(
            header::ORIGIN,
            HeaderValue::from_static("https://offtask.example"),
        );
        assert!(browser_origin(&cfg, &headers).is_err());
        let value = secret("ot_browser_");
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("{COOKIE}={value}")).unwrap(),
        );
        assert_eq!(browser(&headers).unwrap(), digest(&value));
        headers.append(
            header::COOKIE,
            HeaderValue::from_str(&format!("{COOKIE}={value}")).unwrap(),
        );
        assert!(browser(&headers).is_err());
    }
    struct Fixture {
        app: Production,
        account: String,
        base: String,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    async fn fixture() -> Fixture {
        let url = env::var("TEST_DATABASE_URL")
            .expect("OAuth PostgreSQL tests require disposable TEST_DATABASE_URL");
        let options = PgConnectOptions::from_str(&url)
            .unwrap()
            .disable_statement_logging();
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(options.clone())
            .await
            .unwrap();
        let schema = format!("oauth_test_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect_with(options.options([("search_path", schema.as_str())]))
            .await
            .unwrap();
        let mut app = Production::new(pool, "https://offtask.example")
            .await
            .unwrap();
        app.oauth = Some(Arc::new(cfg()));
        let account = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO accounts(id,name,bio,declared_dot,declaration_version,created) VALUES($1,'Synthetic <dot>','Synthetic only',TRUE,1,$2)").bind(&account).bind(now()).execute(&app.pool).await.unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let router = app.router();
        let task = tokio::spawn(async move {
            crate::http_server::serve(listener, router, std::future::pending())
                .await
                .unwrap();
        });
        Fixture {
            app,
            account,
            base,
            task,
        }
    }
    fn authorization_query() -> String {
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("response_type", "code")
            .append_pair("client_id", "synthetic-client")
            .append_pair("redirect_uri", "https://chatgpt.example/oauth/callback")
            .append_pair("resource", "https://offtask.example/mcp")
            .append_pair("scope", "offtask:read offtask:ack offtask:events")
            .append_pair("state", "synthetic-state")
            .append_pair("code_challenge_method", "S256")
            .append_pair("code_challenge", &pkce_challenge(&"v".repeat(43)).unwrap())
            .finish()
    }
    fn input(html: &str, name: &str) -> String {
        html.split(&format!("name=\"{name}\" value=\""))
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap()
            .into()
    }
    async fn start(f: &Fixture) -> (Fields, HeaderMap) {
        let response = authorize(&f.app, &authorization_query()).await.unwrap();
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let body = String::from_utf8(
            to_bytes(response.into_body(), 65536)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        let form = HashMap::from([
            ("request".into(), input(&body, "request")),
            ("csrf".into(), input(&body, "csrf")),
        ]);
        let headers = HeaderMap::from_iter([
            (
                header::ORIGIN,
                HeaderValue::from_static("https://offtask.example"),
            ),
            (header::COOKIE, HeaderValue::from_str(&cookie).unwrap()),
        ]);
        (form, headers)
    }
    async fn code(f: &Fixture) -> String {
        let (mut form, headers) = start(f).await;
        let ticket = issue_link_ticket(&f.app.pool, config(&f.app).unwrap(), &f.account)
            .await
            .unwrap();
        form.insert(
            "ticket".into(),
            ticket["linkTicket"].as_str().unwrap().into(),
        );
        let response = select_box(&f.app, &headers, &form).await.unwrap();
        let body = String::from_utf8(
            to_bytes(response.into_body(), 65536)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(body.contains(&f.account));
        assert!(body.contains("Synthetic &lt;dot&gt;"));
        form.remove("ticket");
        form.insert("decision".into(), "approve".into());
        let response = consent(&f.app, &headers, &form).await.unwrap();
        let target = Url::parse(
            response
                .headers()
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .unwrap();
        let values = target.query_pairs().into_owned().collect::<Fields>();
        assert_eq!(values["iss"], "https://offtask.example");
        assert_eq!(values["state"], "synthetic-state");
        assert!(consent(&f.app, &headers, &form).await.is_err());
        values["code"].clone()
    }
    fn code_form(code: &str) -> Fields {
        Fields::from([
            ("grant_type".into(), "authorization_code".into()),
            ("client_id".into(), "synthetic-client".into()),
            ("resource".into(), "https://offtask.example/mcp".into()),
            (
                "redirect_uri".into(),
                "https://chatgpt.example/oauth/callback".into(),
            ),
            ("code".into(), code.into()),
            ("code_verifier".into(), "v".repeat(43)),
        ])
    }
    fn refresh_form(refresh: &str) -> Fields {
        Fields::from([
            ("grant_type".into(), "refresh_token".into()),
            ("client_id".into(), "synthetic-client".into()),
            ("resource".into(), "https://offtask.example/mcp".into()),
            ("refresh_token".into(), refresh.into()),
        ])
    }
    async fn authenticate(f: &Fixture, token: &str, scope: &str) -> Result<Grant> {
        let mut tx = write_tx(&f.app.pool).await?;
        let headers = HeaderMap::from_iter([(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )]);
        actor_tx(&f.app, &mut tx, &headers, scope).await
    }
    #[tokio::test]
    #[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
    async fn oauth_code_pkce_client_redirect_resource_expiry_and_replay() {
        let f = fixture().await;
        let code = code(&f).await;
        let original = code_form(&code);
        for (key, value) in [
            ("client_id", "wrong-client"),
            ("resource", "https://offtask.example/other"),
            ("redirect_uri", "https://chatgpt.example/oauth/callback/"),
            ("code_verifier", "v"),
            ("code_verifier", &"w".repeat(43)),
        ] {
            let mut bad = original.clone();
            bad.insert(key.into(), value.into());
            assert!(exchange(&f.app, &bad).await.is_err(), "{key}");
        }
        let tokens = exchange(&f.app, &original).await.unwrap();
        assert_eq!(tokens["expires_in"], 900);
        assert_eq!(
            authenticate(&f, tokens["access_token"].as_str().unwrap(), READ_SCOPE)
                .await
                .unwrap()
                .account,
            f.account
        );
        assert!(exchange(&f.app, &original).await.is_err());
        assert!(
            authenticate(&f, tokens["access_token"].as_str().unwrap(), READ_SCOPE)
                .await
                .is_err()
        );
        let code = super::tests::code(&f).await;
        sqlx::query("UPDATE oauth_codes SET expires=$1 WHERE digest=$2")
            .bind(unix())
            .bind(digest(&code))
            .execute(&f.app.pool)
            .await
            .unwrap();
        assert!(exchange(&f.app, &code_form(&code)).await.is_err());
        let leaked: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM oauth_tokens WHERE digest LIKE 'ot_%'")
                .fetch_one(&f.app.pool)
                .await
                .unwrap();
        assert_eq!(leaked, 0);
    }
    #[tokio::test]
    #[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
    async fn oauth_csrf_ticket_binding_and_denial() {
        let f = fixture().await;
        let (mut form, headers) = start(&f).await;
        let ticket = issue_link_ticket(&f.app.pool, config(&f.app).unwrap(), &f.account)
            .await
            .unwrap();
        form.insert(
            "ticket".into(),
            ticket["linkTicket"].as_str().unwrap().into(),
        );
        let mut bad = form.clone();
        bad.insert("csrf".into(), secret("ot_csrf_"));
        assert!(select_box(&f.app, &headers, &bad).await.is_err());
        let (_, other_browser) = start(&f).await;
        assert!(select_box(&f.app, &other_browser, &form).await.is_err());
        let mut cross = headers.clone();
        cross.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.example"),
        );
        assert!(select_box(&f.app, &cross, &form).await.is_err());
        let mut no_origin = headers.clone();
        no_origin.remove(header::ORIGIN);
        assert!(select_box(&f.app, &no_origin, &form).await.is_err());
        select_box(&f.app, &headers, &form).await.unwrap();
        assert!(select_box(&f.app, &headers, &form).await.is_err());
        let (mut other, other_headers) = start(&f).await;
        other.insert("ticket".into(), form["ticket"].clone());
        assert!(select_box(&f.app, &other_headers, &other).await.is_err());
        form.remove("ticket");
        form.insert("decision".into(), "deny".into());
        let response = consent(&f.app, &headers, &form).await.unwrap();
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.contains("error=access_denied"));
        assert!(location.contains("iss="));
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oauth_grants")
            .fetch_one(&f.app.pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
        let (mut form, headers) = start(&f).await;
        let ticket = issue_link_ticket(&f.app.pool, config(&f.app).unwrap(), &f.account)
            .await
            .unwrap();
        sqlx::query("UPDATE oauth_link_tickets SET expires=$1")
            .bind(unix())
            .execute(&f.app.pool)
            .await
            .unwrap();
        form.insert(
            "ticket".into(),
            ticket["linkTicket"].as_str().unwrap().into(),
        );
        assert!(select_box(&f.app, &headers, &form).await.is_err());
    }
    #[tokio::test]
    #[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
    async fn oauth_concurrent_refresh_reuse_revokes_the_winner() {
        let f = fixture().await;
        let tokens = exchange(&f.app, &code_form(&code(&f).await)).await.unwrap();
        let form = refresh_form(tokens["refresh_token"].as_str().unwrap());
        let (a, b) = tokio::join!(exchange(&f.app, &form), exchange(&f.app, &form));
        assert_ne!(a.is_ok(), b.is_ok());
        let winner = a.or(b).unwrap();
        assert!(
            authenticate(&f, winner["access_token"].as_str().unwrap(), READ_SCOPE)
                .await
                .is_err()
        );
        assert!(
            exchange(
                &f.app,
                &refresh_form(winner["refresh_token"].as_str().unwrap())
            )
            .await
            .is_err()
        );
    }
    #[tokio::test]
    #[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
    async fn oauth_rotation_revocation_disabled_box_and_config_binding() {
        let f = fixture().await;
        let tokens = exchange(&f.app, &code_form(&code(&f).await)).await.unwrap();
        let form = refresh_form(tokens["refresh_token"].as_str().unwrap());
        let mut elevated = form.clone();
        elevated.insert("scope".into(), "offtask:admin".into());
        assert!(exchange(&f.app, &elevated).await.is_err());
        let rotated = exchange(&f.app, &form).await.unwrap();
        let token = rotated["access_token"].as_str().unwrap();
        let grant = authenticate(&f, token, READ_SCOPE).await.unwrap();
        assert_ne!(rotated["refresh_token"], tokens["refresh_token"]);
        sqlx::query("UPDATE accounts SET disabled=TRUE WHERE id=$1")
            .bind(&f.account)
            .execute(&f.app.pool)
            .await
            .unwrap();
        assert!(authenticate(&f, token, READ_SCOPE).await.is_err());
        assert!(
            exchange(
                &f.app,
                &refresh_form(rotated["refresh_token"].as_str().unwrap())
            )
            .await
            .is_err()
        );
        sqlx::query("UPDATE accounts SET disabled=FALSE WHERE id=$1")
            .bind(&f.account)
            .execute(&f.app.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE oauth_grants SET resource='https://other.example/mcp' WHERE id=$1")
            .bind(&grant.id)
            .execute(&f.app.pool)
            .await
            .unwrap();
        assert!(authenticate(&f, token, READ_SCOPE).await.is_err());
        sqlx::query("UPDATE oauth_grants SET resource='https://offtask.example/mcp',issuer='https://other.example' WHERE id=$1").bind(&grant.id).execute(&f.app.pool).await.unwrap();
        assert!(authenticate(&f, token, READ_SCOPE).await.is_err());
        sqlx::query("UPDATE oauth_grants SET issuer='https://offtask.example',scopes=ARRAY['offtask:read'] WHERE id=$1").bind(&grant.id).execute(&f.app.pool).await.unwrap();
        assert_eq!(authenticate(&f, token, ACK_SCOPE).await.unwrap_err().0, 403);
        let form = Fields::from([
            ("client_id".into(), "synthetic-client".into()),
            ("token".into(), token.into()),
        ]);
        revoke(&f.app, &form).await.unwrap();
        revoke(&f.app, &form).await.unwrap();
        assert!(authenticate(&f, token, READ_SCOPE).await.is_err());
        let (_, token) = test_grant(&f.app, &f.account, READ_SCOPE).await;
        sqlx::query("UPDATE oauth_tokens SET expires=$1 WHERE digest=$2")
            .bind(unix())
            .bind(digest(&token))
            .execute(&f.app.pool)
            .await
            .unwrap();
        assert!(authenticate(&f, &token, READ_SCOPE).await.is_err());
    }
    #[tokio::test]
    #[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
    async fn oauth_http_metadata_forms_exact_authorization_and_headers() {
        let f = fixture().await;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        for path in [
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
            "/.well-known/oauth-authorization-server",
        ] {
            let r = client
                .get(format!("{}{path}", f.base))
                .header("Host", "offtask.example")
                .send()
                .await
                .unwrap();
            assert_eq!(r.status(), 200);
            assert_eq!(r.headers()["cache-control"], "no-store");
            let value: Value = r.json().await.unwrap();
            if path.ends_with("oauth-authorization-server") {
                assert_eq!(value["code_challenge_methods_supported"], json!(["S256"]));
                assert_eq!(
                    value["token_endpoint_auth_methods_supported"],
                    json!(["none"])
                );
                assert_eq!(
                    value["authorization_response_iss_parameter_supported"],
                    true
                );
                assert!(value.get("registration_endpoint").is_none());
            } else {
                assert_eq!(value["resource"], "https://offtask.example/mcp");
            }
        }
        let query = authorization_query();
        for bad in [
            query.replace("S256", "plain"),
            query.replace("synthetic-client", "wrong-client"),
            query.replace("callback", "callback-evil"),
            query.replace("%2Fmcp", "%2Felsewhere"),
            format!("{query}&resource=https://evil.example"),
            query.replace("offtask%3Aread", "offtask%3Awrite"),
        ] {
            assert!(authorize(&f.app, &bad).await.is_err(), "{bad}");
        }
        let r = client
            .get(format!("{}/oauth/authorize?{query}", f.base))
            .header("Host", "offtask.example")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let cookie = r.headers()["set-cookie"].to_str().unwrap();
        for flag in ["__Host-", "HttpOnly", "Secure", "SameSite=Lax", "Path=/"] {
            assert!(cookie.contains(flag));
        }
        assert!(
            r.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'")
        );
        let r = client
            .post(format!("{}/oauth/token", f.base))
            .header("Host", "offtask.example")
            .json(&json!({"code":"never-json"}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 415);
        let r = client
            .post(format!("{}/oauth/token?code=bad", f.base))
            .header("Host", "offtask.example")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body("client_id=synthetic-client")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400);
        let r = client
            .post(format!("{}/oauth/token", f.base))
            .header("Host", "offtask.example")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body("client_id=synthetic-client&client_id=synthetic-client")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400);
    }

    #[tokio::test]
    #[ignore = "requires disposable TEST_DATABASE_URL; run --include-ignored"]
    async fn oauth_http_complete_consent_exchange_refresh_revoke() {
        let f = fixture().await;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let initial = client
            .get(format!(
                "{}/oauth/authorize?{}",
                f.base,
                authorization_query()
            ))
            .header("Host", "offtask.example")
            .send()
            .await
            .unwrap();
        assert_eq!(initial.status(), 200);
        assert_eq!(initial.headers()["referrer-policy"], "same-origin");
        let cookie = initial.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let page = initial.text().await.unwrap();
        let request = input(&page, "request");
        let csrf = input(&page, "csrf");
        let ticket = issue_link_ticket(&f.app.pool, config(&f.app).unwrap(), &f.account)
            .await
            .unwrap();
        let selected = client
            .post(format!("{}/oauth/authorize", f.base))
            .header("Host", "offtask.example")
            .header("Origin", "https://offtask.example")
            .header("Cookie", &cookie)
            .form(&[
                ("request", request.as_str()),
                ("csrf", csrf.as_str()),
                ("ticket", ticket["linkTicket"].as_str().unwrap()),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(selected.status(), 200);
        assert_eq!(selected.headers()["referrer-policy"], "same-origin");
        assert!(selected.text().await.unwrap().contains(&f.account));
        let approved = client
            .post(format!("{}/oauth/consent", f.base))
            .header("Host", "offtask.example")
            .header("Origin", "https://offtask.example")
            .header("Cookie", &cookie)
            .form(&[
                ("request", request.as_str()),
                ("csrf", csrf.as_str()),
                ("decision", "approve"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(approved.status(), 303);
        assert_eq!(approved.headers()["referrer-policy"], "no-referrer");
        assert!(
            approved.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("form-action 'self' https://chatgpt.example")
        );
        let destination = Url::parse(approved.headers()["location"].to_str().unwrap()).unwrap();
        assert_eq!(
            destination.origin().ascii_serialization(),
            "https://chatgpt.example"
        );
        let params = destination.query_pairs().into_owned().collect::<Fields>();
        assert_eq!(params["state"], "synthetic-state");
        assert_eq!(params["iss"], "https://offtask.example");
        let issued = client
            .post(format!("{}/oauth/token", f.base))
            .header("Host", "offtask.example")
            .form(&code_form(&params["code"]))
            .send()
            .await
            .unwrap();
        assert_eq!(issued.status(), 200);
        assert_eq!(issued.headers()["pragma"], "no-cache");
        assert_eq!(issued.headers()["cache-control"], "no-store");
        let issued: Value = issued.json().await.unwrap();
        let refreshed = client
            .post(format!("{}/oauth/token", f.base))
            .header("Host", "offtask.example")
            .form(&refresh_form(issued["refresh_token"].as_str().unwrap()))
            .send()
            .await
            .unwrap();
        assert_eq!(refreshed.status(), 200);
        let refreshed: Value = refreshed.json().await.unwrap();
        let access = refreshed["access_token"].as_str().unwrap();
        assert!(authenticate(&f, access, READ_SCOPE).await.is_ok());
        let revoked = client
            .post(format!("{}/oauth/revoke", f.base))
            .header("Host", "offtask.example")
            .form(&[
                ("client_id", "synthetic-client"),
                ("token", access),
                ("token_type_hint", "access_token"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(revoked.status(), 200);
        assert!(authenticate(&f, access, READ_SCOPE).await.is_err());
    }
}
