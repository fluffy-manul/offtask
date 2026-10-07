// Browser-test harness only; not copied into the deployment image.
use std::{
    collections::BTreeMap,
    io::{self, Read},
};
#[tokio::main]
async fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let v: serde_json::Value = serde_json::from_str(&input).unwrap();
    let tokens: BTreeMap<String, String> =
        serde_json::from_value(v["tokens"].clone()).unwrap_or_default();
    let mode = offtask::Mode::parse(v["mode"].as_str().unwrap(), Some("test")).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("https://{}", listener.local_addr().unwrap());
    let app = offtask::App::new(
        mode.clone(),
        v["database"].as_str().unwrap(),
        tokens,
        if mode == offtask::Mode::Preview {
            Some(origin.as_str())
        } else {
            None
        },
    )
    .unwrap();
    println!("{}", listener.local_addr().unwrap().port());
    offtask::http_server::serve(listener, app.router(), std::future::pending())
        .await
        .unwrap();
}
