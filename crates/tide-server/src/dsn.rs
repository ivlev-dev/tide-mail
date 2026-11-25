use std::time::{SystemTime, UNIX_EPOCH};

use crate::outbound::OutboundJob;

pub fn is_dsn(raw: &[u8]) -> bool {
    let head = String::from_utf8_lossy(&raw[..raw.len().min(8192)]).to_ascii_lowercase();
    head.contains("multipart/report") && head.contains("report-type=delivery-status")
}

#[allow(dead_code)]
pub fn build_failure_dsn(job: &OutboundJob, hostname: &str, reason: &str) -> Vec<u8> {
    build_failure_dsn_with_status(job, hostname, reason, "5.0.0")
}

pub fn build_failure_dsn_with_status(
    job: &OutboundJob,
    hostname: &str,
    reason: &str,
    status: &str,
) -> Vec<u8> {
    build_delivery_dsn(
        job,
        hostname,
        reason,
        status,
        "Failure",
        "failed permanently",
        "failed",
    )
}

pub fn build_delayed_dsn(job: &OutboundJob, hostname: &str) -> Vec<u8> {
    build_delivery_dsn(
        job,
        hostname,
        "delivery time expired",
        "4.4.7",
        "Delay",
        "delayed",
        "delayed",
    )
}

fn build_delivery_dsn(
    job: &OutboundJob,
    hostname: &str,
    reason: &str,
    status: &str,
    subject: &str,
    explanation: &str,
    action: &str,
) -> Vec<u8> {
    let now = now_millis() / 1000;
    let arrived = if job.created_at > 0 {
        job.created_at
    } else {
        now
    };
    let date = mail_parser::DateTime::from_timestamp(now).to_rfc822();
    let boundary = format!("----tide-dsn-{}", now);
    let message_id = if job.message_id.is_empty() {
        "<unknown@tide>".to_string()
    } else {
        format!("<{}@tide>", job.message_id)
    };
    let mut out = Vec::new();
    out.extend_from_slice(
        format!(
            "From: Mail Delivery System <MAILER-DAEMON@{hostname}>\r\n\
             To: <{}>\r\n\
             Subject: Delivery Status Notification ({subject})\r\n\
             Date: {date}\r\n\
             Message-ID: <dsn-{}@tide>\r\n\
             Auto-Submitted: auto-replied\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: multipart/report; report-type=delivery-status; boundary=\"{boundary}\"\r\n\r\n",
            job.from,
            now
        )
        .as_bytes(),
    );
    out.extend_from_slice(
        format!("--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n").as_bytes(),
    );
    out.extend_from_slice(
        format!(
            "This is the mail system at {hostname}.\n\n\
             Delivery to the following recipient {explanation}:\n\n    {}\n\n\
             Reason: {reason}\n\n\
             The original message headers are attached.\n",
            job.to
        )
        .as_bytes(),
    );
    out.extend_from_slice(
        format!("\r\n--{boundary}\r\nContent-Type: message/delivery-status\r\n\r\n").as_bytes(),
    );
    out.extend_from_slice(
        format!(
            "Reporting-MTA: dns; {hostname}\r\n\
             X-Tide-Queue-ID: {}\r\n\
             Arrival-Date: {}\r\n{}\
             Final-Recipient: rfc822; {}\r\n\
             {}\
             Action: {action}\r\n\
             Status: {status}\r\n\
             Diagnostic-Code: smtp; {reason}\r\n\
             Original-Message-ID: {message_id}\r\n{}\
             ",
            job.id,
            mail_parser::DateTime::from_timestamp(arrived).to_rfc822(),
            dsn_dates(job),
            job.to,
            job.orcpt
                .as_ref()
                .map(|orcpt| format!("Original-Recipient: {orcpt}\r\n"))
                .unwrap_or_default(),
            job.envid
                .as_ref()
                .map(|envid| format!("Original-Envelope-Id: {envid}\r\n"))
                .unwrap_or_default()
        )
        .as_bytes(),
    );
    let full = job.dsn_ret.as_deref() == Some("FULL");
    if full {
        out.extend_from_slice(
            format!("\r\n--{boundary}\r\nContent-Type: message/rfc822\r\n\r\n").as_bytes(),
        );
        out.extend_from_slice(&job.raw);
        out.extend_from_slice(format!("\r\n\r\n--{boundary}--\r\n").as_bytes());
    } else {
        out.extend_from_slice(
            format!("\r\n--{boundary}\r\nContent-Type: text/rfc822-headers\r\n\r\n").as_bytes(),
        );
        let headers_end = job
            .raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap_or(job.raw.len().min(4096));
        out.extend_from_slice(&job.raw[..headers_end]);
        out.extend_from_slice(format!("\r\n\r\n--{boundary}--\r\n").as_bytes());
    }
    out
}

fn dsn_dates(job: &OutboundJob) -> String {
    let mut fields = String::new();
    if let Some(deadline) = deliver_by_deadline(job) {
        let date = mail_parser::DateTime::from_timestamp(deadline).to_rfc822();
        fields.push_str(&format!("Deliver-By-Date: {date}\r\n"));
    }
    if let Some(release) = &job.future_release {
        let value = if let Some(seconds) = release.strip_prefix("for;") {
            format!("for;{seconds}")
        } else if let Some(epoch) = release.strip_prefix("until;") {
            let timestamp = epoch.parse::<i64>().unwrap_or(0);
            let date = chrono::DateTime::from_timestamp(timestamp, 0)
                .map(|date| date.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                .unwrap_or_else(|| epoch.to_string());
            format!("until;{date}")
        } else {
            release.clone()
        };
        fields.push_str(&format!("Future-Release-Request: {value}\r\n"));
    }
    fields
}

fn deliver_by_deadline(job: &OutboundJob) -> Option<i64> {
    let seconds = job
        .deliver_by
        .as_deref()?
        .split(';')
        .next()?
        .parse::<i64>()
        .ok()?;
    Some(job.created_at.max(0).saturating_add(seconds))
}

pub fn build_success_dsn(job: &OutboundJob, hostname: &str) -> Vec<u8> {
    let now = now_millis() / 1000;
    let date = mail_parser::DateTime::from_timestamp(now).to_rfc822();
    let boundary = format!("----tide-dsn-ok-{now}");
    let message_id = if job.message_id.is_empty() {
        "<unknown@tide>".to_string()
    } else {
        format!("<{}@tide>", job.message_id)
    };
    let mut out = Vec::new();
    out.extend_from_slice(
        format!(
            "From: Mail Delivery System <MAILER-DAEMON@{hostname}>\r\n\
             To: <{}>\r\n\
             Subject: Delivery Status Notification (Success)\r\n\
             Date: {date}\r\n\
             Message-ID: <dsn-ok-{now}@tide>\r\n\
             Auto-Submitted: auto-replied\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: multipart/report; report-type=delivery-status; boundary=\"{boundary}\"\r\n\r\n",
            job.from
        )
        .as_bytes(),
    );
    out.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n\
             Delivery to the following recipient succeeded:\n\n    {}\n",
            job.to
        )
        .as_bytes(),
    );
    out.extend_from_slice(
        format!("\r\n--{boundary}\r\nContent-Type: message/delivery-status\r\n\r\n").as_bytes(),
    );
    out.extend_from_slice(
        format!(
            "Reporting-MTA: dns; {hostname}\r\n\
             X-Tide-Queue-ID: {}\r\n\r\n\
             Final-Recipient: rfc822; {}\r\n\
             {}\
             {}\
             Action: delivered\r\n\
             Status: 2.0.0\r\n\
             Original-Message-ID: {message_id}\r\n",
            job.id,
            job.to,
            job.orcpt
                .as_ref()
                .map(|orcpt| format!("Original-Recipient: {orcpt}\r\n"))
                .unwrap_or_default(),
            job.envid
                .as_ref()
                .map(|envid| format!("Original-Envelope-Id: {envid}\r\n"))
                .unwrap_or_default()
        )
        .as_bytes(),
    );
    out.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    out
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job() -> OutboundJob {
        OutboundJob {
            id: "job-1".into(),
            from: "alice@mail.local".into(),
            to: "bob@example.com".into(),
            raw: b"From: alice@mail.local\r\nTo: bob@example.com\r\nSubject: hi\r\n\r\nbody"
                .to_vec(),
            message_id: "m1".into(),
            dsn: false,
            require_tls: false,
            dsn_ret: None,
            envid: None,
            notify: None,
            orcpt: None,
            future_release: None,
            deliver_by: None,
            created_at: 0,
        }
    }

    #[test]
    fn includes_envelope_and_full_body() {
        let mut job = job();
        job.dsn_ret = Some("FULL".into());
        job.envid = Some("env-1".into());
        job.orcpt = Some("rfc822;bob@example.com".into());
        let dsn = build_failure_dsn(&job, "mail.local", "timeout");
        let text = String::from_utf8_lossy(&dsn);
        assert!(text.contains("Original-Envelope-Id: env-1"));
        assert!(text.contains("Original-Recipient: rfc822;bob@example.com"));
        assert!(text.contains("Content-Type: message/rfc822"));
        assert!(text.contains("body"));
    }

    #[test]
    fn builds_success_dsn() {
        let mut job = job();
        job.notify = Some("SUCCESS".into());
        let dsn = build_success_dsn(&job, "mail.local");
        let text = String::from_utf8_lossy(&dsn);
        assert!(text.contains("Action: delivered"));
        assert!(text.contains("Status: 2.0.0"));
    }

    #[test]
    fn builds_and_detects_dsn() {
        let raw = build_failure_dsn(&job(), "mail.local", "connection refused");
        let text = String::from_utf8_lossy(&raw);
        assert!(text.contains("multipart/report"));
        assert!(text.contains("Final-Recipient: rfc822; bob@example.com"));
        assert!(text.contains("Original-Message-ID: <m1@tide>"));
        assert!(is_dsn(&raw));
    }
}
