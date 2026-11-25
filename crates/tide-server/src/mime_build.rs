use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use tide_proto::AttachmentData;
use uuid::Uuid;

pub fn build_message(
    from: &str,
    to: &[String],
    subject: &str,
    text: &str,
    html: Option<&str>,
    attachments: &[AttachmentData],
) -> Result<Vec<u8>, String> {
    for value in [from, subject] {
        if value.contains('\r') || value.contains('\n') {
            return Err("header injection".into());
        }
    }
    for attachment in attachments {
        if attachment.filename.contains('\r') || attachment.filename.contains('\n') {
            return Err("header injection".into());
        }
    }
    let date = mail_parser::DateTime::from_timestamp(now_millis() / 1000).to_rfc822();
    let message_id = format!("<{}@tide>", Uuid::new_v4());
    let mut out = Vec::new();
    out.extend_from_slice(format!("From: {from}\r\n").as_bytes());
    out.extend_from_slice(format!("To: {}\r\n", to.join(", ")).as_bytes());
    out.extend_from_slice(format!("Subject: {subject}\r\n").as_bytes());
    out.extend_from_slice(format!("Date: {date}\r\n").as_bytes());
    out.extend_from_slice(format!("Message-ID: {message_id}\r\n").as_bytes());
    out.extend_from_slice(b"MIME-Version: 1.0\r\n");

    let boundary = format!("----tide-{}", Uuid::new_v4());
    let alternative = html.is_some();
    if attachments.is_empty() {
        if alternative {
            out.extend_from_slice(
                format!("Content-Type: multipart/alternative; boundary=\"{boundary}\"\r\n\r\n")
                    .as_bytes(),
            );
            append_text_part(&mut out, &boundary, "text/plain", text);
            append_text_part(&mut out, &boundary, "text/html", html.unwrap_or_default());
            out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        } else {
            out.extend_from_slice(
                b"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n",
            );
            out.extend_from_slice(text.replace('\n', "\r\n").as_bytes());
        }
        return Ok(out);
    }

    let mixed = format!("{boundary}-mixed");
    let alt = format!("{boundary}-alt");
    out.extend_from_slice(
        format!("Content-Type: multipart/mixed; boundary=\"{mixed}\"\r\n\r\n").as_bytes(),
    );
    if alternative {
        out.extend_from_slice(format!("--{mixed}\r\n").as_bytes());
        out.extend_from_slice(
            format!("Content-Type: multipart/alternative; boundary=\"{alt}\"\r\n\r\n").as_bytes(),
        );
        append_text_part(&mut out, &alt, "text/plain", text);
        append_text_part(&mut out, &alt, "text/html", html.unwrap_or_default());
        out.extend_from_slice(format!("--{alt}--\r\n").as_bytes());
    } else {
        out.extend_from_slice(format!("--{mixed}\r\n").as_bytes());
        out.extend_from_slice(
            b"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n",
        );
        out.extend_from_slice(text.replace('\n', "\r\n").as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    for attachment in attachments {
        out.extend_from_slice(format!("--{mixed}\r\n").as_bytes());
        out.extend_from_slice(
            format!(
                "Content-Type: {}\r\nContent-Disposition: attachment; filename=\"{}\"\r\nContent-Transfer-Encoding: base64\r\n\r\n",
                sanitize_token(&attachment.content_type),
                sanitize_filename(&attachment.filename)
            )
            .as_bytes(),
        );
        let encoded = BASE64.encode(&attachment.data);
        for line in encoded.as_bytes().chunks(76) {
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(format!("--{mixed}--\r\n").as_bytes());
    Ok(out)
}

fn append_text_part(out: &mut Vec<u8>, boundary: &str, content_type: &str, body: &str) {
    out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    out.extend_from_slice(
        format!(
            "Content-Type: {content_type}; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
        )
        .as_bytes(),
    );
    out.extend_from_slice(body.replace('\n', "\r\n").as_bytes());
    out.extend_from_slice(b"\r\n");
}

fn sanitize_token(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '+' | '-' | '.'))
        .collect()
}

fn sanitize_filename(value: &str) -> String {
    value
        .chars()
        .filter(|ch| !matches!(ch, '"' | '\\' | '\r' | '\n'))
        .collect()
}

fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_attachment_message() {
        let raw = build_message(
            "alice@mail.local",
            &["bob@example.com".into()],
            "Report",
            "Hello",
            None,
            &[AttachmentData {
                filename: "report.txt".into(),
                content_type: "text/plain".into(),
                data: b"attachment".to_vec(),
            }],
        )
        .unwrap();
        let text = String::from_utf8_lossy(&raw);
        assert!(text.contains("multipart/mixed"));
        assert!(text.contains("filename=\"report.txt\""));
        assert!(text.contains("YXR0YWNobWVudA=="));
    }
}
