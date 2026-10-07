use std::{
    env,
    io::{self, Read},
};
fn main() {
    if let Err(error) = run() {
        eprintln!("{}", error.1);
        std::process::exit(1);
    }
}
fn run() -> offtask::Result<()> {
    if env::var("OFFTASK_MODE").as_deref() == Ok("production") {
        return tokio::runtime::Runtime::new()
            .map_err(|_| offtask::Error(500, "Runtime unavailable".into()))?
            .block_on(async {
                let pool = offtask::production::database_from_env().await?;
                let args = env::args().skip(1).collect::<Vec<_>>();
                let value = offtask::production::administer(&pool, &args).await?;
                println!("{value}");
                Ok(())
            });
    }
    if offtask::Mode::parse(
        &env::var("OFFTASK_MODE").unwrap_or_default(),
        env::var("NODE_ENV").ok().as_deref(),
    )? != offtask::Mode::LocalAuth
    {
        return Err(offtask::Error(
            400,
            "Administration requires local-auth mode".into(),
        ));
    }
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty()
        || !matches!(
            args[0].as_str(),
            "pending" | "approve" | "rotate" | "revoke"
        )
        || args.len() != if args[0] == "pending" { 1 } else { 2 }
    {
        return Err(offtask::Error(
            400,
            "Usage: offtask-admin pending | approve ID | rotate ID | revoke ID".into(),
        ));
    }
    let path = env::var("OFFTASK_DATABASE").unwrap_or_else(|_| "data/agents.sqlite".into());
    let mut db =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA busy_timeout=2000;")?;
    let mut digest = String::new();
    if args[0] == "rotate" {
        io::stdin()
            .take(67)
            .read_to_string(&mut digest)
            .map_err(|_| offtask::Error(400, "Invalid digest input".into()))?;
        if digest.len() > 66 {
            return Err(offtask::Error(400, "Expected only a SHA256 digest".into()));
        }
    }
    let result = offtask::administer(
        &mut db,
        &args[0],
        args.get(1).map(String::as_str).unwrap_or(""),
        Some(digest.trim()),
    )?;
    println!("{result}");
    Ok(())
}
