mod app;
mod auth;
mod config;
mod convert;
mod dsn;
mod email_auth;
mod http;
mod mime_build;
mod net;
mod outbound;
mod reporting;
mod scan_queue;
mod smtp;
mod sync_server;
mod tls;
mod tls_policy;
mod virus_scan;

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
    let store_options = {
        let options = StoreOptions::default()
            .with_data_lanes(config.server.data_lanes)
            .with_lane_capacity(
                config
                    .server
                    .lane_capacity_mb
                    .saturating_mul(1024 * 1024)
                    .max(4 * 1024 * 1024),
            );
        let options = if let Some(blob_dir) = &config.server.blob_dir {
            options.with_blob_dir(blob_dir)
        } else {
            options
        };
        if config.blob.backend.eq_ignore_ascii_case("s3") {
            options.with_s3(tide_store::S3Config {
                bucket: config.blob.bucket.clone(),
                region: config.blob.region.clone(),
                endpoint: config.blob.endpoint.clone(),
                access_key_id: config.blob.access_key_id.clone(),
                secret_access_key: config.blob.secret_access_key.clone(),
                prefix: config.blob.prefix.clone(),
                allow_http: config.blob.allow_http,
            })
        } else {
            options
        }
    };
    let db = loop {
        match Db::open(&config.server.data_path, store_options.clone()) {
            Ok(db) => break db,
            Err(tide_store::StoreError::Locked) if config.server.standby => {
                eprintln!("standby: database is locked by primary, retrying");
                std::thread::sleep(std::time::Duration::from_secs(
                    config.server.standby_retry_secs.max(1),
                ));
            }
            Err(error) => {
                eprintln!("не удалось открыть хранилище: {error}");
                std::process::exit(1);
            }
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
    let email_auth = if config.email_auth.enabled {
        match mail_auth::MessageAuthenticator::new_system_conf() {
            Ok(authenticator) => Some(std::sync::Arc::new(authenticator)),
            Err(error) => {
                eprintln!("email auth init: {error}");
                None
            }
        }
    } else {
        None
    };
    let dkim = if config.dkim.is_enabled() {
        Some(config.dkim.clone())
    } else {
        None
    };
    let spam = if config.spam.enabled {
        let mut filters: Vec<Box<dyn tide_spam::SpamFilter>> =
            vec![Box::new(tide_spam::RuleFilter)];
        if !config.spam.dnsbl_zones.is_empty() {
            filters.push(Box::new(tide_spam::DnsblFilter::new(
                config.spam.dnsbl_zones.clone(),
            )));
        }
        if let Some(command) = config.spam.external_command.clone() {
            filters.push(Box::new(tide_spam::ExternalFilter::new(command)));
        }
        Some(std::sync::Arc::new(tide_spam::SpamEngine::new(
            filters,
            config.spam.threshold,
            config.spam.reject_threshold,
        )))
    } else {
        None
    };
    let antivirus = if config.antivirus.enabled {
        Some(std::sync::Arc::new(virus_scan::VirusScanner::new(
            config.antivirus.clone(),
        )))
    } else {
        None
    };
    let scan_queue = if config.antivirus.enabled && config.antivirus.async_scan {
        antivirus.clone().map(|scanner| {
            scan_queue::ScanQueue::start(
                db.clone(),
                scanner,
                config.antivirus.quarantine_folder.clone(),
                config.antivirus.infected_folder.clone(),
            )
        })
    } else {
        None
    };
    let reports = if config.server.dmarc_reports || config.server.tls_rpt {
        let dir = config
            .server
            .report_dir
            .clone()
            .unwrap_or_else(|| config.server.data_path.with_file_name("reports"));
        Some(reporting::Reports::new(
            dir,
            config.server.hostname.clone(),
            config.server.dmarc_reports,
            config.server.tls_rpt,
        ))
    } else {
        None
    };
    let outbound = if config.server.outbound_enabled {
        let outbound_dir = config
            .server
            .outbound_dir
            .clone()
            .unwrap_or_else(|| config.server.data_path.with_file_name("outbound"));
        Some(outbound::OutboundQueue::start(
            outbound_dir,
            config.server.hostname.clone(),
            dkim.clone(),
            config.server.outbound_tls,
            config.server.dsn_enabled,
            tls_policy::MtaStsCache::new(
                config.server.mta_sts,
                Some(config.server.data_path.with_file_name("mta-sts")),
            ),
            config.server.dane,
            reports.clone(),
            email_auth.clone(),
        ))
    } else {
        None
    };
    let app = App::new(
        config.clone(),
        db,
        registry,
        tls,
        outbound,
        email_auth,
        spam,
        antivirus,
        scan_queue,
        reports,
    );

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
    if let Some(address) = &config.server.smtps_addr {
        println!("  SMTPS {address}");
    }
    if let Some(address) = &config.server.lmtp_addr {
        println!("  LMTP  {address}");
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
                .spawn(move || run_worker(app, index))
                .expect("worker thread"),
        );
    }
    for thread in threads {
        let _ = thread.join();
    }
}

fn run_worker(app: Arc<App>, worker_index: usize) {
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
                    let use_tls = app.config.server.http_tls && app.tls.is_some();
                    monoio::spawn(http::serve_http(app, listener, use_tls));
                }
                Err(error) => eprintln!("http bind {address}: {error}"),
            }
        }
        if let Some(address) = &app.config.server.smtp_addr {
            match TcpListener::bind_with_config(address, &options) {
                Ok(listener) => {
                    let app = Arc::clone(&app);
                    monoio::spawn(smtp::serve_smtp(app, listener, false, false, false));
                }
                Err(error) => eprintln!("smtp bind {address}: {error}"),
            }
        }
        if let Some(address) = &app.config.server.submission_addr {
            match TcpListener::bind_with_config(address, &options) {
                Ok(listener) => {
                    let app = Arc::clone(&app);
                    monoio::spawn(smtp::serve_smtp(app, listener, true, false, false));
                }
                Err(error) => eprintln!("submission bind {address}: {error}"),
            }
        }
        if let Some(address) = &app.config.server.smtps_addr {
            let address = address.clone();
            match TcpListener::bind_with_config(&address, &options) {
                Ok(listener) => {
                    let app = Arc::clone(&app);
                    monoio::spawn(smtp::serve_smtp(app, listener, false, true, false));
                }
                Err(error) => eprintln!("smtps bind {address}: {error}"),
            }
        }
        if let Some(address) = &app.config.server.lmtp_addr {
            let address = address.clone();
            match TcpListener::bind_with_config(&address, &options) {
                Ok(listener) => {
                    let app = Arc::clone(&app);
                    monoio::spawn(smtp::serve_smtp(app, listener, false, false, true));
                }
                Err(error) => eprintln!("lmtp bind {address}: {error}"),
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
        if worker_index == 0 {
            if let (Some(reports), Some(outbound)) = (app.reports.clone(), app.outbound.clone()) {
                reports.spawn_flusher(outbound, std::time::Duration::from_secs(3600));
            }
        }
        if worker_index == 0 && app.config.server.snapshot_interval_secs > 0 {
            let db = app.db.clone();
            let interval = app.config.server.snapshot_interval_secs;
            monoio::spawn(async move {
                loop {
                    monoio::time::sleep(std::time::Duration::from_secs(interval)).await;
                    if let Err(error) = db.snapshot().await {
                        eprintln!("snapshot: {error}");
                    }
                }
            });
        }
        std::future::pending::<()>().await;
        #[allow(unreachable_code)]
        {
            let _ = &app;
        }
    });
}
