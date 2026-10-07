use offtask::{App, Mode, PROFILES};
use rand::RngCore;
use std::{
    collections::BTreeMap,
    env,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{}", error.1);
        std::process::exit(1);
    }
}
async fn run() -> offtask::Result<()> {
    let mode = Mode::parse(
        &env::var("OFFTASK_MODE").unwrap_or_default(),
        env::var("NODE_ENV").ok().as_deref(),
    )?;
    let preview = mode == Mode::Preview;
    let args = env::args().skip(1).collect::<Vec<_>>();
    if !args.is_empty() && (args != ["--public-preview"] || !preview) {
        return Err(offtask::Error(
            400,
            "This entrypoint requires public-preview mode".into(),
        ));
    }
    let port = env::var("PORT")
        .unwrap_or_else(|_| if preview { "80" } else { "3000" }.into())
        .parse::<u16>()
        .map_err(|_| offtask::Error(400, "PORT must be a valid port number".into()))?;
    if preview && port != 80 {
        return Err(offtask::Error(
            400,
            "Public preview must listen on port 80".into(),
        ));
    }
    let mut tokens = BTreeMap::new();
    if mode == Mode::Development {
        for (id, _, _) in PROFILES {
            let mut bytes = [0u8; 32];
            rand::rng().fill_bytes(&mut bytes);
            tokens.insert(
                id.to_string(),
                bytes.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            );
        }
    }
    let path = if preview {
        ":memory:".into()
    } else {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create("data")
            .map_err(|_| offtask::Error(500, "Cannot create private data directory".into()))?;
        // Dedicated private directory also protects WAL/SHM files created by SQLite.
        std::fs::set_permissions("data", std::fs::Permissions::from_mode(0o700))
            .map_err(|_| offtask::Error(500, "Cannot protect data directory".into()))?;
        env::var("OFFTASK_DATABASE").unwrap_or_else(|_| {
            if mode == Mode::Development {
                "data/offtask.sqlite"
            } else {
                "data/agents.sqlite"
            }
            .into()
        })
    };
    let app = App::new(
        mode.clone(),
        &path,
        tokens.clone(),
        env::var("PUBLIC_ORIGIN").ok().as_deref(),
    )?;
    let listener =
        tokio::net::TcpListener::bind((if preview { "0.0.0.0" } else { "127.0.0.1" }, port))
            .await
            .map_err(|_| offtask::Error(500, "Cannot bind listener".into()))?;
    println!(
        "Offtask {} listening on {}",
        mode.name(),
        listener.local_addr().unwrap()
    );
    for (id, token) in tokens {
        println!("{id}: {token}");
    }
    offtask::http_server::serve(listener, app.router(), async {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("signal handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
    })
    .await
    .map_err(|_| offtask::Error(500, "HTTP server failed".into()))
}
