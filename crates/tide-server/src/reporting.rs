use std::collections::BTreeMap;
use std::fs::{OpenOptions, create_dir_all, read_to_string};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::email_auth::DmarcInfo;
use crate::outbound::OutboundQueue;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DmarcEvent {
    ts: i64,
    domain: String,
    rua: Vec<String>,
    source_ip: String,
    disposition: String,
    dkim: String,
    spf: String,
    header_from: String,
    policy: String,
    adkim: String,
    aspf: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TlsEvent {
    ts: i64,
    domain: String,
    rua: Vec<String>,
    policy_type: String,
    result_type: String,
    sending_mta: String,
    receiving_mta: String,
}

pub struct Reports {
    dir: PathBuf,
    hostname: String,
    dmarc_enabled: bool,
    tls_enabled: bool,
}

impl Reports {
    pub fn new(
        dir: impl Into<PathBuf>,
        hostname: impl Into<String>,
        dmarc_enabled: bool,
        tls_enabled: bool,
    ) -> Arc<Self> {
        let dir = dir.into();
        let _ = create_dir_all(&dir);
        Arc::new(Self {
            dir,
            hostname: hostname.into(),
            dmarc_enabled,
            tls_enabled,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_dmarc(
        &self,
        domain: &str,
        rua: &[String],
        source_ip: &str,
        disposition: &str,
        dkim: &str,
        spf: &str,
        header_from: &str,
        policy: &str,
        adkim: &str,
        aspf: &str,
    ) {
        if !self.dmarc_enabled || rua.is_empty() {
            return;
        }
        let event = DmarcEvent {
            ts: crate::auth::now_millis() / 1000,
            domain: domain.to_string(),
            rua: rua.to_vec(),
            source_ip: source_ip.to_string(),
            disposition: disposition.to_string(),
            dkim: dkim.to_string(),
            spf: spf.to_string(),
            header_from: header_from.to_string(),
            policy: policy.to_string(),
            adkim: adkim.to_string(),
            aspf: aspf.to_string(),
        };
        let _ = append_json(&self.dir.join("dmarc.jsonl"), &event);
    }

    pub fn record_tls_failure(
        &self,
        domain: &str,
        rua: &[String],
        policy_type: &str,
        result_type: &str,
        sending_mta: &str,
        receiving_mta: &str,
    ) {
        if !self.tls_enabled || rua.is_empty() {
            return;
        }
        let event = TlsEvent {
            ts: crate::auth::now_millis() / 1000,
            domain: domain.to_string(),
            rua: rua.to_vec(),
            policy_type: policy_type.to_string(),
            result_type: result_type.to_string(),
            sending_mta: sending_mta.to_string(),
            receiving_mta: receiving_mta.to_string(),
        };
        let _ = append_json(&self.dir.join("tlsrpt.jsonl"), &event);
    }

    pub fn flush(&self, outbound: &OutboundQueue) -> usize {
        let mut sent = 0;
        sent += self.flush_dmarc(outbound);
        sent += self.flush_tls(outbound);
        sent
    }

    pub fn spawn_flusher(self: &Arc<Self>, outbound: Arc<OutboundQueue>, interval: Duration) {
        let reports = Arc::clone(self);
        std::thread::Builder::new()
            .name("tide-reports".into())
            .spawn(move || {
                std::thread::sleep(interval);
                loop {
                    let sent = reports.flush(&outbound);
                    if sent > 0 {
                        eprintln!("reports: sent {sent}");
                    }
                    std::thread::sleep(interval);
                }
            })
            .ok();
    }

    fn flush_dmarc(&self, outbound: &OutboundQueue) -> usize {
        let path = self.dir.join("dmarc.jsonl");
        let Ok(raw) = read_to_string(&path) else {
            return 0;
        };
        let events: Vec<DmarcEvent> = raw
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        if events.is_empty() {
            return 0;
        }
        let mut groups: BTreeMap<(String, String), Vec<DmarcEvent>> = BTreeMap::new();
        for event in events {
            let key = (event.domain.clone(), event.rua.join(","));
            groups.entry(key).or_default().push(event);
        }
        let mut sent = 0;
        for ((domain, rua), records) in groups {
            let xml = build_dmarc_xml(&self.hostname, &domain, &records);
            let report_id = format!("{}-{}", domain, crate::auth::now_millis());
            let raw = build_report_message(
                &self.hostname,
                &rua,
                &format!("Report domain: {domain} Submitter: {}", self.hostname),
                &report_id,
                "application/xml",
                &xml,
            );
            let mut job = OutboundQueue::job("", &rua, raw);
            job.message_id = report_id;
            if outbound.enqueue(job) {
                sent += 1;
            }
        }
        let _ = std::fs::remove_file(path);
        sent
    }

    fn flush_tls(&self, outbound: &OutboundQueue) -> usize {
        let path = self.dir.join("tlsrpt.jsonl");
        let Ok(raw) = read_to_string(&path) else {
            return 0;
        };
        let events: Vec<TlsEvent> = raw
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        if events.is_empty() {
            return 0;
        }
        let mut groups: BTreeMap<(String, String), Vec<TlsEvent>> = BTreeMap::new();
        for event in events {
            let key = (event.domain.clone(), event.rua.join(","));
            groups.entry(key).or_default().push(event);
        }
        let mut sent = 0;
        for ((domain, rua), records) in groups {
            let body = build_tlsrpt_json(&self.hostname, &domain, &records);
            let report_id = format!("{}-{}", domain, crate::auth::now_millis());
            let raw = build_report_message(
                &self.hostname,
                &rua,
                &format!("Report domain: {domain} Submitter: {}", self.hostname),
                &report_id,
                "application/tlsrpt+json",
                &body,
            );
            let mut job = OutboundQueue::job("", &rua, raw);
            job.message_id = report_id;
            if outbound.enqueue(job) {
                sent += 1;
            }
        }
        let _ = std::fs::remove_file(path);
        sent
    }
}

pub fn dmarc_failure_message(
    info: &DmarcInfo,
    hostname: &str,
    source_ip: &str,
    mail_from: &str,
    raw: &[u8],
) -> Vec<u8> {
    let now = crate::auth::now_millis() / 1000;
    let date = mail_parser::DateTime::from_timestamp(now).to_rfc822();
    let boundary = format!("----tide-feedback-{now}");
    let mut out = Vec::new();
    out.extend_from_slice(
        format!(
            "From: Mail Reports <postmaster@{hostname}>\r\n\
             To: <{}>\r\n\
             Subject: DMARC failure report for {}\r\n\
             Date: {date}\r\n\
             Message-ID: <dmarc-failure-{now}@tide>\r\n\
             Auto-Submitted: auto-generated\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: multipart/report; report-type=feedback-report; boundary=\"{boundary}\"\r\n\r\n",
            info.ruf.join(", "),
            escape(&info.domain)
        )
        .as_bytes(),
    );
    out.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n\
             This is a DMARC failure report for a message claiming to be from {}.\n",
            escape(&info.header_from)
        )
        .as_bytes(),
    );
    out.extend_from_slice(
        format!("\r\n--{boundary}\r\nContent-Type: message/feedback-report\r\n\r\n").as_bytes(),
    );
    out.extend_from_slice(
        format!(
            "Feedback-Type: auth-failure\r\n\
             User-Agent: Tide Mail\r\n\
             Version: 1\r\n\
             Original-Mail-From: {mail_from}\r\n\
             Arrival-Date: {date}\r\n\
             Source-IP: {source_ip}\r\n\
             Reported-Domain: {}\r\n\
             Authentication-Results: dkim={}; spf={}; dmarc={}\r\n",
            escape(&info.domain),
            info.dkim,
            info.spf,
            info.disposition
        )
        .as_bytes(),
    );
    out.extend_from_slice(
        format!("\r\n--{boundary}\r\nContent-Type: text/rfc822-headers\r\n\r\n").as_bytes(),
    );
    let headers_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or(raw.len().min(4096));
    out.extend_from_slice(&raw[..headers_end]);
    out.extend_from_slice(format!("\r\n\r\n--{boundary}--\r\n").as_bytes());
    out
}

fn append_json<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let line = serde_json::to_string(value).map_err(std::io::Error::other)?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")
}

fn build_report_message(
    hostname: &str,
    recipient: &str,
    subject: &str,
    report_id: &str,
    content_type: &str,
    body: &[u8],
) -> Vec<u8> {
    let date = mail_parser::DateTime::from_timestamp(crate::auth::now_millis() / 1000).to_rfc822();
    let mut out = Vec::new();
    out.extend_from_slice(
        format!(
            "From: Mail Reports <postmaster@{hostname}>\r\n\
             To: <{recipient}>\r\n\
             Subject: {subject}\r\n\
             Date: {date}\r\n\
             Message-ID: <{report_id}@tide>\r\n\
             Auto-Submitted: auto-generated\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: {content_type}\r\n\
             Content-Transfer-Encoding: 8bit\r\n\r\n"
        )
        .as_bytes(),
    );
    out.extend_from_slice(body);
    out
}

fn build_dmarc_xml(hostname: &str, domain: &str, records: &[DmarcEvent]) -> Vec<u8> {
    let begin = records.iter().map(|record| record.ts).min().unwrap_or(0);
    let end = records.iter().map(|record| record.ts).max().unwrap_or(0);
    let first = records.first();
    let mut xml = String::new();
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<feedback>\n  <report_metadata>\n");
    xml.push_str("    <org_name>Tide Mail</org_name>\n");
    xml.push_str(&format!(
        "    <email>postmaster@{}</email>\n",
        escape(hostname)
    ));
    xml.push_str(&format!(
        "    <report_id>{}-{}</report_id>\n",
        escape(domain),
        end
    ));
    xml.push_str(&format!(
        "    <date_range><begin>{begin}</begin><end>{end}</end></date_range>\n"
    ));
    xml.push_str("  </report_metadata>\n  <policy_published>\n");
    xml.push_str(&format!("    <domain>{}</domain>\n", escape(domain)));
    xml.push_str(&format!(
        "    <adkim>{}</adkim>\n    <aspf>{}</aspf>\n",
        first.map(|record| record.adkim.as_str()).unwrap_or("r"),
        first.map(|record| record.aspf.as_str()).unwrap_or("r")
    ));
    xml.push_str(&format!(
        "    <p>{}</p>\n    <sp>{}</sp>\n    <pct>100</pct>\n",
        first.map(|record| record.policy.as_str()).unwrap_or("none"),
        first.map(|record| record.policy.as_str()).unwrap_or("none")
    ));
    xml.push_str("  </policy_published>\n");
    for record in records {
        xml.push_str("  <record>\n    <row>\n");
        xml.push_str(&format!(
            "      <source_ip>{}</source_ip>\n      <count>1</count>\n",
            escape(&record.source_ip)
        ));
        xml.push_str("      <policy_evaluated>\n");
        xml.push_str(&format!(
            "        <disposition>{}</disposition>\n        <dkim>{}</dkim>\n        <spf>{}</spf>\n",
            escape(&record.disposition),
            escape(&record.dkim),
            escape(&record.spf)
        ));
        xml.push_str("      </policy_evaluated>\n    </row>\n    <identifiers>\n");
        xml.push_str(&format!(
            "      <header_from>{}</header_from>\n    </identifiers>\n",
            escape(&record.header_from)
        ));
        xml.push_str("    <auth_results>\n");
        xml.push_str(&format!(
            "      <dkim><domain>{}</domain><result>{}</result></dkim>\n",
            escape(&record.header_from),
            escape(&record.dkim)
        ));
        xml.push_str(&format!(
            "      <spf><domain>{}</domain><result>{}</result></spf>\n",
            escape(&record.header_from),
            escape(&record.spf)
        ));
        xml.push_str("    </auth_results>\n  </record>\n");
    }
    xml.push_str("</feedback>\n");
    xml.into_bytes()
}

fn build_tlsrpt_json(hostname: &str, domain: &str, records: &[TlsEvent]) -> Vec<u8> {
    let begin = records.iter().map(|record| record.ts).min().unwrap_or(0);
    let end = records.iter().map(|record| record.ts).max().unwrap_or(0);
    let policy_type = records
        .first()
        .map(|record| record.policy_type.as_str())
        .unwrap_or("smtp-tls");
    let failures = records
        .iter()
        .map(|record| {
            json!({
                "result-type": record.result_type,
                "sending-mta-ip": record.sending_mta,
                "receiving-mta-ip": record.receiving_mta,
                "failed-session-count": 1
            })
        })
        .collect::<Vec<_>>();
    let report = json!({
        "organization-name": "Tide Mail",
        "date-range": {
            "start-datetime": format_ts(begin),
            "end-datetime": format_ts(end)
        },
        "contact-info": format!("postmaster@{hostname}"),
        "report-id": format!("{domain}-{end}"),
        "policies": [{
            "policy": {
                "policy-type": policy_type,
                "policy-string": ["version: STSv1".to_string(), "mode: enforce".to_string()],
                "domain": domain
            },
            "summary": {
                "total-successful-session-count": 0,
                "total-failure-session-count": records.len()
            },
            "failure-details": failures
        }]
    });
    serde_json::to_vec_pretty(&report).unwrap_or_default()
}

fn format_ts(seconds: i64) -> String {
    mail_parser::DateTime::from_timestamp(seconds).to_rfc822()
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> DmarcEvent {
        DmarcEvent {
            ts: 100,
            domain: "example.com".into(),
            rua: vec!["dmarc@example.com".into()],
            source_ip: "192.0.2.1".into(),
            disposition: "none".into(),
            dkim: "pass".into(),
            spf: "fail".into(),
            header_from: "example.com".into(),
            policy: "none".into(),
            adkim: "r".into(),
            aspf: "r".into(),
        }
    }

    #[test]
    fn builds_aggregate_xml() {
        let xml =
            String::from_utf8(build_dmarc_xml("mail.local", "example.com", &[event()])).unwrap();
        assert!(xml.contains("<source_ip>192.0.2.1</source_ip>"));
        assert!(xml.contains("<dkim>pass</dkim>"));
        assert!(xml.contains("<policy_published>"));
    }

    #[test]
    fn builds_tls_report_json() {
        let raw = build_tlsrpt_json(
            "mail.local",
            "example.com",
            &[TlsEvent {
                ts: 100,
                domain: "example.com".into(),
                rua: vec!["tls@example.com".into()],
                policy_type: "sts".into(),
                result_type: "certificate-expired".into(),
                sending_mta: "192.0.2.1".into(),
                receiving_mta: "192.0.2.2".into(),
            }],
        );
        let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(value["policies"][0]["policy"]["policy-type"], "sts");
        assert_eq!(
            value["policies"][0]["failure-details"][0]["failed-session-count"],
            1
        );
    }

    #[test]
    fn escapes_xml() {
        assert_eq!(escape("a<b&c"), "a&lt;b&amp;c");
    }
}
