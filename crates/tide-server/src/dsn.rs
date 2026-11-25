use std::time::{SystemTime, UNIX_EPOCH};

use crate::outbound::OutboundJob;

pub fn is_dsn(raw: &[u8]) -> bool {
    let head = String::from_utf8_lossy(&raw[..raw.len().min(8192)]).to_ascii_lowercase();
    head.contains("multipart/report") && head.contains("report-type=delivery-status")
}

pub fn build_failure_dsn(job: &OutboundJob, hostname: &str, reason: &str) -> Vec<u8> {
    let now = now_millis() / 1000;
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
             Subject: Delivery Status Notification (Failure)\r\n\
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
             Delivery to the following recipient failed permanently:\n\n    {}\n\n\
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
             X-Tide-Queue-ID: {}\r\n\r\n\
             Final-Recipient: rfc822; {}\r\n\
             Action: failed\r\n\
             Status: 5.0.0\r\n\
             Diagnostic-Code: smtp; {reason}\r\n\
             Original-Message-ID: {message_id}\r\n",
            job.id, job.to
        )
        .as_bytes(),
    );
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
        }
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
