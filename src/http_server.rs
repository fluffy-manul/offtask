//! HTTP/1 transport with explicit header timing and bounded graceful shutdown.
//! App Platform terminates HTTPS/HTTP2 at its edge and forwards HTTP to this service.
use axum::Router;
use hyper::server::conn::http1;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::{future::Future, io, time::Duration};
use tokio::{net::TcpListener, sync::watch, task::JoinSet};

pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(20);

pub async fn serve(
    listener: TcpListener,
    router: Router,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    let (stop, _) = watch::channel(());
    let mut connections = JoinSet::new();
    let limit = std::sync::Arc::new(tokio::sync::Semaphore::new(256));
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            Some(_) = connections.join_next(), if !connections.is_empty() => {},
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let Ok(permit) = limit.clone().try_acquire_owned() else { drop(stream); continue; };
                let service = TowerToHyperService::new(router.clone());
                let mut stopping = stop.subscribe();
                connections.spawn(async move {
                    let _permit = permit;
                    let mut builder = http1::Builder::new();
                    builder.timer(TokioTimer::new()).header_read_timeout(HEADER_READ_TIMEOUT).max_headers(64).max_buf_size(32768);
                    let connection = builder.serve_connection(TokioIo::new(stream), service);
                    tokio::pin!(connection);
                    tokio::select! {
                        _ = &mut connection => {},
                        _ = stopping.changed() => {
                            connection.as_mut().graceful_shutdown();
                            let _ = connection.await;
                        }
                    }
                });
            }
        }
    }
    drop(listener);
    let _ = stop.send(());
    if tokio::time::timeout(SHUTDOWN_TIMEOUT, async {
        while connections.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    Ok(())
}
