use std::sync::Arc;
use std::sync::mpsc::{Sender, channel};
use std::time::Duration;

use tide_smtp::SmtpClient;

#[derive(Debug, Clone)]
pub struct OutboundJob {
    pub from: String,
    pub to: String,
    pub raw: Vec<u8>,
}

#[derive(Clone)]
pub struct OutboundQueue {
    tx: Sender<OutboundJob>,
}

impl OutboundQueue {
    pub fn start(hostname: String) -> Arc<Self> {
        let (tx, rx) = channel::<OutboundJob>();
        std::thread::Builder::new()
            .name("tide-outbound".into())
            .spawn(move || {
                while let Ok(job) = rx.recv() {
                    deliver_with_retry(&hostname, &job);
                }
            })
            .expect("outbound worker");
        Arc::new(Self { tx })
    }

    pub fn enqueue(&self, job: OutboundJob) -> bool {
        self.tx.send(job).is_ok()
    }
}

fn deliver_with_retry(hostname: &str, job: &OutboundJob) {
    let mut delay = Duration::from_secs(1);
    for attempt in 1..=3 {
        match deliver_once(hostname, job) {
            Ok(()) => {
                eprintln!("outbound {} -> {}: delivered", job.from, job.to);
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
    eprintln!("outbound {} -> {}: giving up", job.from, job.to);
}

fn deliver_once(hostname: &str, job: &OutboundJob) -> Result<(), String> {
    let domain = job
        .to
        .rsplit_once('@')
        .map(|(_, domain)| domain)
        .ok_or_else(|| "recipient has no domain".to_string())?;
    let mut client = SmtpClient::connect((domain, 25u16)).map_err(|error| error.to_string())?;
    let greeting = client.read_reply().map_err(|error| error.to_string())?;
    if greeting.code != 220 {
        return Err(format!("unexpected greeting: {greeting}"));
    }
    client.ehlo(hostname).map_err(|error| error.to_string())?;
    client
        .send_message(&job.from, std::slice::from_ref(&job.to), &job.raw)
        .map_err(|error| error.to_string())?;
    let _ = client.quit();
    Ok(())
}
