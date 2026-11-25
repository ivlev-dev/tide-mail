mod app;
mod auth;
mod config;
mod convert;
mod http;
mod net;
mod outbound;
mod smtp;
mod sync_server;
mod tls;

use std::sync::Arc;

use monoio::RuntimeBuilder;
use monoio::blocking::DefaultThreadPool;
use monoio::net::{ListenerOpts, TcpListener};
use tide_store::{Db, StoreOptions};

use crate::app::App;
use crate::auth::Registry;
use crate::config::Config;

fn main() {
    let config_path = std::env::args()
        .skip(1)
        .find(|argument| !argument.starts_with('-'))
        .unwrap_or_else(|| "tide.toml".to_string());
    let config = match Config::load_or_create(&config_path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    };
    let db = match Db::open(
        &config.server.data_path,
        StoreOptions::default()
            .with_data_lanes(config.server.data_lanes)
            .with_lane_capacity(
                config
                    .server
                    .lane_capacity_mb
                    .saturating_mul(1024 * 1024)
                    .max(4 * 1024 * 1024),
            ),
    ) {
        Ok(db) => db,
        Err(error) => {
            eprintln!("не удалось открыть хранилище: {error}");
            std::process::exit(1);
        }
    };
    let registry = match Registry::new(&config.accounts, config.server.token_ttl_hours) {
        Ok(registry) => registry,
        Err(error) => {
            eprintln!("не удалось инициализировать аккаунты: {error}");
            std::process::exit(1);
        }
    };
    let tls = match tls::build_acceptor(&config.tls, &config.server.hostname) {
        Ok(tls) => tls,
        Err(error) => {
            eprintln!("TLS: {error}");
            std::process::exit(1);
        }
    };
    let outbound = if config.server.outbound_enabled {
        Some(outbound::OutboundQueue::start(
            config.server.hostname.clone(),
        ))
    } else {
        None
    };
    let app = App::new(config.clone(), db, registry, tls, outbound);

    println!(
        "Tide Mail: {} ({} воркеров)",
        config.server.hostname, config.server.workers
    );
    if !config.server.http_addr.is_empty() {
        println!("  HTTP  {}", config.server.http_addr);
    }
    if let Some(address) = &config.server.smtp_addr {
        println!("  SMTP  {address}");
    }
    if let Some(address) = &config.server.submission_addr {
        println!("  SUB   {address}");
    }
    if let Some(address) = &config.server.sync_addr {
        println!("  SYNC  {address}");
    }

    let mut threads = Vec::new();
    for index in 0..config.server.workers {
        let app = Arc::clone(&app);
        let name = format!("tide-worker-{index}");
        threads.push(
            std::thread::Builder::new()
                .name(name)
                .spawn(move || run_worker(app))
                .expect("worker thread"),
        );
    }
    for thread in threads {
        let _ = thread.join();
    }
}

fn run_worker(app: Arc<App>) {
    let mut runtime = RuntimeBuilder::<monoio::IoUringDriver>::new()
        .enable_all()
        .attach_thread_pool(Box::new(DefaultThreadPool::new(4)))
        .build()
        .expect("io_uring runtime");
    runtime.block_on(async move {
        let options = ListenerOpts::new().reuse_port(true).reuse_addr(true);
        if !app.config.server.http_addr.is_empty() {
            let address = app.config.server.http_addr.clone();
            match TcpListener::bind_with_config(&address, &options) {
                Ok(listener) => {
                    let app = Arc::clone(&app);
                    monoio::spawn(http::serve_http(app, listener));
                }
                Err(error) => eprintln!("http bind {address}: {error}"),
            }
        }
        if let Some(address) = &app.config.server.smtp_addr {
            match TcpListener::bind_with_config(address, &options) {
                Ok(listener) => {
                    let app = Arc::clone(&app);
                    monoio::spawn(smtp::serve_smtp(app, listener, false));
                }
                Err(error) => eprintln!("smtp bind {address}: {error}"),
            }
        }
        if let Some(address) = &app.config.server.submission_addr {
            match TcpListener::bind_with_config(address, &options) {
                Ok(listener) => {
                    let app = Arc::clone(&app);
                    monoio::spawn(smtp::serve_smtp(app, listener, true));
                }
                Err(error) => eprintln!("submission bind {address}: {error}"),
            }
        }
        if let Some(address) = &app.config.server.sync_addr {
            match TcpListener::bind_with_config(address, &options) {
                Ok(listener) => {
                    let app = Arc::clone(&app);
                    let use_tls = app.tls.is_some();
                    monoio::spawn(sync_server::serve_sync(app, listener, use_tls));
                }
                Err(error) => eprintln!("sync bind {address}: {error}"),
            }
        }
        std::future::pending::<()>().await;
        #[allow(unreachable_code)]
        {
            let _ = &app;
        }
    });
}
