use std::fs;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{Sender, channel};
use std::time::Duration;

use hickory_resolver::Resolver;
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use serde::{Deserialize, Serialize};
use tide_smtp::SmtpClient;
use uuid::Uuid;

use crate::config::DkimSettings;
use crate::tls_policy::MtaStsCache;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundJob {
    pub id: String,
    pub from: String,
    pub to: String,
    pub raw: Vec<u8>,
    #[serde(default)]
    pub message_id: String,
    #[serde(default)]
    pub dsn: bool,
    #[serde(default)]
    pub require_tls: bool,
    #[serde(default)]
    pub dsn_ret: Option<String>,
    #[serde(default)]
    pub envid: Option<String>,
}

#[derive(Clone)]
pub struct OutboundQueue {
    tx: Sender<OutboundJob>,
    dir: PathBuf,
}

impl OutboundQueue {
    pub fn start(
        dir: impl Into<PathBuf>,
        hostname: String,
        dkim: Option<DkimSettings>,
        tls: bool,
        dsn_enabled: bool,
        mta_sts: Arc<MtaStsCache>,
        dane: bool,
    ) -> Arc<Self> {
        let dir = dir.into();
        let _ = fs::create_dir_all(&dir);
        let (tx, rx) = channel::<OutboundJob>();
        let workdir = dir.clone();
        let sender = tx.clone();
        let policy = Arc::clone(&mta_sts);
        let mut initial = Vec::new();
        for entry in fs::read_dir(&workdir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("bin") {
                continue;
            }
            if let Ok(bytes) = fs::read(&path) {
                if let Ok(job) = bincode::deserialize::<OutboundJob>(&bytes) {
                    initial.push(job);
                }
            }
        }
        std::thread::Builder::new()
            .name("tide-outbound".into())
            .spawn(move || {
                for job in initial {
                    deliver_with_retry(
                        &hostname,
                        dkim.as_ref(),
                        tls,
                        dsn_enabled,
                        &workdir,
                        &sender,
                        &policy,
                        dane,
                        &job,
                    );
                }
                while let Ok(job) = rx.recv() {
                    deliver_with_retry(
                        &hostname,
                        dkim.as_ref(),
                        tls,
                        dsn_enabled,
                        &workdir,
                        &sender,
                        &policy,
                        dane,
                        &job,
                    );
                }
            })
            .expect("outbound worker");
        Arc::new(Self { tx, dir })
    }

    pub fn enqueue(&self, mut job: OutboundJob) -> bool {
        if job.id.is_empty() {
            job.id = Uuid::new_v4().to_string();
        }
        let Some(job) = write_job(&self.dir, job) else {
            return false;
        };
        self.tx.send(job).is_ok()
    }

    pub fn job(from: impl Into<String>, to: impl Into<String>, raw: Vec<u8>) -> OutboundJob {
        OutboundJob {
            id: String::new(),
            from: from.into(),
            to: to.into(),
            raw,
            message_id: String::new(),
            dsn: false,
            require_tls: false,
            dsn_ret: None,
            envid: None,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn deliver_with_retry(
    hostname: &str,
    dkim: Option<&DkimSettings>,
    tls: bool,
    dsn_enabled: bool,
    dir: &Path,
    sender: &Sender<OutboundJob>,
    policy: &Arc<MtaStsCache>,
    dane: bool,
    job: &OutboundJob,
) {
    let raw = match dkim {
        Some(settings) => match crate::email_auth::sign_dkim(settings, &job.raw) {
            Ok(raw) => raw,
            Err(error) => {
                eprintln!("dkim signing {} -> {}: {error}", job.from, job.to);
                job.raw.clone()
            }
        },
        None => job.raw.clone(),
    };
    let mut delay = Duration::from_secs(1);
    for attempt in 1..=3 {
        match deliver_once(hostname, tls, policy, dane, job, &raw) {
            Ok(()) => {
                eprintln!("outbound {} -> {}: delivered", job.from, job.to);
                let _ = fs::remove_file(dir.join(format!("{}.bin", job.id)));
                return;
            }
            Err(error) => {
                eprintln!(
                    "outbound {} -> {} attempt {attempt}: {error}",
                    job.from, job.to
                );
                if attempt < 3 {
                    std::thread::sleep(delay);
                    delay = delay.saturating_mul(3);
                }
            }
        }
    }
    eprintln!(
        "outbound {} -> {}: giving up, job kept at {}",
        job.from,
        job.to,
        dir.join(format!("{}.bin", job.id)).display()
    );
    if dsn_enabled && !job.dsn && !job.from.is_empty() {
        let dsn = crate::dsn::build_failure_dsn(job, hostname, "delivery attempt failed");
        let dsn_job = OutboundJob {
            id: String::new(),
            from: String::new(),
            to: job.from.clone(),
            raw: dsn,
            message_id: job.message_id.clone(),
            dsn: true,
            require_tls: false,
            dsn_ret: None,
            envid: job.envid.clone(),
        };
        if let Some(dsn_job) = write_job(dir, dsn_job) {
            let _ = sender.send(dsn_job);
        }
        let _ = fs::remove_file(dir.join(format!("{}.bin", job.id)));
    }
}

fn write_job(dir: &Path, mut job: OutboundJob) -> Option<OutboundJob> {
    if job.id.is_empty() {
        job.id = Uuid::new_v4().to_string();
    }
    let path = dir.join(format!("{}.bin", job.id));
    let temp = dir.join(format!("{}.tmp", job.id));
    let bytes = bincode::serialize(&job).ok()?;
    fs::write(&temp, bytes).ok()?;
    fs::rename(&temp, &path).ok()?;
    Some(job)
}

fn deliver_once(
    hostname: &str,
    tls: bool,
    policy: &Arc<MtaStsCache>,
    dane: bool,
    job: &OutboundJob,
    raw: &[u8],
) -> Result<(), String> {
    let domain = job
        .to
        .rsplit_once('@')
        .map(|(_, domain)| domain)
        .ok_or_else(|| "recipient has no domain".to_string())?;
    let hosts = resolve_mx(domain)?;
    let require_tls = policy.check(domain, &hosts, tls)? || job.require_tls;
    let mut last_error = String::new();
    for host in hosts {
        match deliver_host(hostname, tls, dane, require_tls, &host, job, raw) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

fn deliver_host(
    hostname: &str,
    tls: bool,
    dane: bool,
    require_tls: bool,
    host: &str,
    job: &OutboundJob,
    raw: &[u8],
) -> Result<(), String> {
    let stream = TcpStream::connect((host, 25u16)).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(60)))
        .map_err(|error| error.to_string())?;
    let mut client = SmtpClient::new(stream);
    let greeting = client.read_reply().map_err(|error| error.to_string())?;
    if greeting.code != 220 {
        return Err(format!("unexpected greeting: {greeting}"));
    }
    let ehlo = client.ehlo(hostname).map_err(|error| error.to_string())?;
    let offers_starttls = ehlo
        .lines
        .iter()
        .any(|line| line.eq_ignore_ascii_case("STARTTLS"));
    let records = if dane {
        crate::tls_policy::lookup_dane(host).unwrap_or_default()
    } else {
        Vec::new()
    };
    if (require_tls || !records.is_empty()) && !offers_starttls {
        return Err(format!(
            "TLS is required for {host}, but STARTTLS is not offered"
        ));
    }
    if !records.is_empty() && !tls {
        return Err(format!("DANE for {host} requires TLS"));
    }
    if tls && offers_starttls {
        let reply = client
            .command("STARTTLS")
            .map_err(|error| error.to_string())?;
        if reply.code == 220 {
            let stream = client.into_inner();
            let tls_stream = tls_stream(stream, host, &records)?;
            let client = SmtpClient::new(tls_stream);
            return send_with_client(client, hostname, job, raw);
        }
    }
    send_with_client(client, hostname, job, raw)
}

fn send_with_client<S: std::io::Read + std::io::Write>(
    mut client: SmtpClient<S>,
    hostname: &str,
    job: &OutboundJob,
    raw: &[u8],
) -> Result<(), String> {
    client.ehlo(hostname).map_err(|error| error.to_string())?;
    client
        .send_message(&job.from, std::slice::from_ref(&job.to), raw)
        .map_err(|error| error.to_string())?;
    let _ = client.quit();
    Ok(())
}

fn resolve_mx(domain: &str) -> Result<Vec<String>, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    let resolver = Resolver::builder_tokio()
        .map_err(|error| error.to_string())?
        .build()
        .map_err(|error| error.to_string())?;
    let mut records = match runtime.block_on(resolver.mx_lookup(domain)) {
        Ok(lookup) => lookup
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                hickory_resolver::proto::rr::RData::MX(mx) => Some((
                    mx.preference,
                    mx.exchange.to_string().trim_end_matches('.').to_string(),
                )),
                _ => None,
            })
            .collect::<Vec<_>>(),
        Err(_) => Vec::new(),
    };
    records.sort_by_key(|(preference, _)| *preference);
    let mut hosts = records
        .into_iter()
        .map(|(_, host)| host)
        .collect::<Vec<_>>();
    if hosts.is_empty() {
        hosts.push(domain.to_string());
    }
    Ok(hosts)
}

fn tls_stream(
    stream: TcpStream,
    host: &str,
    records: &[crate::tls_policy::DaneRecord],
) -> Result<StreamOwned<ClientConnection, TcpStream>, String> {
    let config = crate::tls_policy::client_config(records)?;
    let server_name = ServerName::try_from(host.to_string()).map_err(|error| error.to_string())?;
    let connection =
        ClientConnection::new(Arc::new(config), server_name).map_err(|error| error.to_string())?;
    Ok(StreamOwned::new(connection, stream))
}
