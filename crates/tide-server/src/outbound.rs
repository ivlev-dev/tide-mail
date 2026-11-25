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
use crate::reporting::Reports;
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
    #[serde(default)]
    pub notify: Option<String>,
    #[serde(default)]
    pub orcpt: Option<String>,
    #[serde(default)]
    pub future_release: Option<String>,
    #[serde(default)]
    pub deliver_by: Option<String>,
    #[serde(default)]
    pub created_at: i64,
}

#[derive(Clone)]
pub struct OutboundQueue {
    tx: Sender<OutboundJob>,
    dir: PathBuf,
}

impl OutboundQueue {
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        dir: impl Into<PathBuf>,
        hostname: String,
        dkim: Option<DkimSettings>,
        tls: bool,
        dsn_enabled: bool,
        mta_sts: Arc<MtaStsCache>,
        dane: bool,
        reports: Option<Arc<Reports>>,
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
                        reports.as_ref(),
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
                        reports.as_ref(),
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
            notify: None,
            orcpt: None,
            future_release: None,
            deliver_by: None,
            created_at: now_secs(),
        }
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn release_at(job: &OutboundJob) -> Option<i64> {
    let value = job.future_release.as_deref()?;
    let seconds = value
        .split_whitespace()
        .next()
        .and_then(|token| token.parse::<u64>().ok())?;
    let base = if job.created_at > 0 {
        job.created_at
    } else {
        now_secs()
    };
    Some(base.saturating_add(seconds as i64))
}

fn deliver_deadline(job: &OutboundJob) -> Option<i64> {
    let value = job.deliver_by.as_deref()?;
    let seconds = value
        .split_whitespace()
        .next()
        .and_then(|token| token.parse::<u64>().ok())?;
    let base = if job.created_at > 0 {
        job.created_at
    } else {
        now_secs()
    };
    Some(base.saturating_add(seconds as i64))
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
    reports: Option<&Arc<Reports>>,
    job: &OutboundJob,
) {
    let now = now_secs();
    if let Some(release) = release_at(job) {
        if now < release {
            let job = job.clone();
            let sender = sender.clone();
            let dir = dir.to_path_buf();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs((release - now).max(1) as u64));
                if let Some(job) = write_job(&dir, job) {
                    let _ = sender.send(job);
                }
            });
            return;
        }
    }
    if let Some(deadline) = deliver_deadline(job) {
        if now >= deadline {
            fail_permanently(
                hostname,
                dsn_enabled,
                dir,
                sender,
                job,
                "delivery time expired",
                true,
            );
            return;
        }
    }
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
    let mut last_error = String::new();
    for attempt in 1..=3 {
        if let Some(deadline) = deliver_deadline(job) {
            if now_secs() >= deadline {
                fail_permanently(
                    hostname,
                    dsn_enabled,
                    dir,
                    sender,
                    job,
                    "delivery time expired",
                    true,
                );
                return;
            }
        }
        match deliver_once(hostname, tls, policy, dane, job, &raw) {
            Ok(()) => {
                eprintln!("outbound {} -> {}: delivered", job.from, job.to);
                let wants_success = job
                    .notify
                    .as_deref()
                    .is_some_and(|notify| notify.split(',').any(|value| value == "SUCCESS"));
                if wants_success && dsn_enabled && !job.dsn && !job.from.is_empty() {
                    let raw = crate::dsn::build_success_dsn(job, hostname);
                    let dsn_job = OutboundJob {
                        id: String::new(),
                        from: String::new(),
                        to: job.from.clone(),
                        raw,
                        message_id: job.message_id.clone(),
                        dsn: true,
                        require_tls: false,
                        dsn_ret: None,
                        envid: job.envid.clone(),
                        notify: None,
                        orcpt: None,
                        future_release: None,
                        deliver_by: None,
                        created_at: now_secs(),
                    };
                    if let Some(dsn_job) = write_job(dir, dsn_job) {
                        let _ = sender.send(dsn_job);
                    }
                }
                let _ = fs::remove_file(dir.join(format!("{}.bin", job.id)));
                return;
            }
            Err(error) => {
                eprintln!(
                    "outbound {} -> {} attempt {attempt}: {error}",
                    job.from, job.to
                );
                last_error = error;
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
    if let Some(reports) = reports {
        record_tls_failure(reports, job, &last_error);
    }
    fail_permanently(
        hostname,
        dsn_enabled,
        dir,
        sender,
        job,
        "delivery attempt failed",
        false,
    );
}

fn record_tls_failure(reports: &Reports, job: &OutboundJob, error: &str) {
    let lower = error.to_ascii_lowercase();
    let (policy_type, result_type) = if lower.contains("mta-sts") {
        ("sts", "sts-policy-fetch-error")
    } else if lower.contains("starttls is not offered") {
        ("smtp-tls", "starttls-not-supported")
    } else if lower.contains("certificate") {
        ("smtp-tls", "certificate-error")
    } else if lower.contains("tls") || lower.contains("handshake") || lower.contains("dane") {
        ("smtp-tls", "tls-connection-failure")
    } else {
        return;
    };
    let Some(domain) = job.to.rsplit_once('@').map(|(_, domain)| domain) else {
        return;
    };
    let Some(rua) = crate::tls_policy::tls_rpt_policy(domain) else {
        return;
    };
    let destinations = rua
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    reports.record_tls_failure(
        domain,
        &destinations,
        policy_type,
        result_type,
        &job.from,
        &job.to,
    );
}

fn fail_permanently(
    hostname: &str,
    dsn_enabled: bool,
    dir: &Path,
    sender: &Sender<OutboundJob>,
    job: &OutboundJob,
    reason: &str,
    force_remove: bool,
) {
    let notify = job.notify.as_deref().unwrap_or("");
    let suppress_dsn = notify.split(',').any(|value| value == "NEVER")
        || (!notify.is_empty() && !notify.split(',').any(|value| value == "FAILURE"));
    let mut reported = false;
    if dsn_enabled && !job.dsn && !job.from.is_empty() && !suppress_dsn {
        let dsn = crate::dsn::build_failure_dsn(job, hostname, reason);
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
            notify: None,
            orcpt: None,
            future_release: None,
            deliver_by: None,
            created_at: now_secs(),
        };
        if let Some(dsn_job) = write_job(dir, dsn_job) {
            let _ = sender.send(dsn_job);
            reported = true;
        }
    }
    if force_remove || reported {
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
    let mut mail = format!("MAIL FROM:<{}>", job.from);
    if let Some(ret) = &job.dsn_ret {
        mail.push_str(&format!(" RET={ret}"));
    }
    if let Some(envid) = &job.envid {
        mail.push_str(&format!(" ENVID={envid}"));
    }
    if job.require_tls {
        mail.push_str(" REQUIRETLS");
    }
    let reply = client.command(&mail).map_err(|error| error.to_string())?;
    if reply.code != 250 {
        return Err(format!("MAIL rejected: {reply}"));
    }
    let mut rcpt = format!("RCPT TO:<{}>", job.to);
    if let Some(notify) = &job.notify {
        rcpt.push_str(&format!(" NOTIFY={notify}"));
    }
    if let Some(orcpt) = &job.orcpt {
        rcpt.push_str(&format!(" ORCPT={orcpt}"));
    }
    let reply = client.command(&rcpt).map_err(|error| error.to_string())?;
    if !(250..260).contains(&reply.code) {
        return Err(format!("RCPT rejected: {reply}"));
    }
    let reply = client.command("DATA").map_err(|error| error.to_string())?;
    if reply.code != 354 {
        return Err(format!("DATA rejected: {reply}"));
    }
    client.write_data(raw).map_err(|error| error.to_string())?;
    let reply = client.read_reply().map_err(|error| error.to_string())?;
    if reply.code != 250 {
        return Err(format!("message rejected: {reply}"));
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn job() -> OutboundJob {
        OutboundJob {
            id: "job".into(),
            from: "alice@example.com".into(),
            to: "bob@example.com".into(),
            raw: Vec::new(),
            message_id: String::new(),
            dsn: false,
            require_tls: false,
            dsn_ret: None,
            envid: None,
            notify: None,
            orcpt: None,
            future_release: None,
            deliver_by: None,
            created_at: 1000,
        }
    }

    #[test]
    fn computes_release_and_deadline() {
        let mut job = job();
        job.future_release = Some("3600".into());
        assert_eq!(release_at(&job), Some(4600));
        job.deliver_by = Some("86400 R".into());
        assert_eq!(deliver_deadline(&job), Some(87400));
    }

    #[test]
    fn ignores_invalid_deadlines() {
        let mut job = job();
        job.future_release = Some("soon".into());
        job.deliver_by = Some("".into());
        assert_eq!(release_at(&job), None);
        assert_eq!(deliver_deadline(&job), None);
    }
}
