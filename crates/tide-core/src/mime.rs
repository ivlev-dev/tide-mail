use mail_parser::{Address, MessageParser};

use crate::{Address as ModelAddress, Attachment, Message};

#[derive(Debug, thiserror::Error)]
pub enum MimeError {
    #[error("пустое сообщение")]
    Empty,
    #[error("не удалось разобрать MIME: {0}")]
    Parse(String),
}

pub fn parse_message(
    raw: &[u8],
    account_id: impl Into<String>,
    mailbox: impl Into<String>,
    id: impl Into<String>,
) -> Result<Message, MimeError> {
    if raw.is_empty() {
        return Err(MimeError::Empty);
    }
    let parsed = MessageParser::new()
        .parse(raw)
        .ok_or_else(|| MimeError::Parse("parser returned no message".into()))?;

    let subject = parsed.subject().unwrap_or_default().to_string();
    let from = convert_addresses(parsed.from().as_ref());
    let to = convert_addresses(parsed.to().as_ref());
    let cc = convert_addresses(parsed.cc().as_ref());
    let bcc = convert_addresses(parsed.bcc().as_ref());
    let message_id = parsed.message_id().unwrap_or_default().to_string();
    let in_reply_to = parsed
        .in_reply_to()
        .and_then(|list| list.first().map(str::to_string));
    let references = parsed
        .references()
        .map(|list| list.iter().map(str::to_string).collect::<Vec<_>>())
        .unwrap_or_default();
    let date = parsed
        .date()
        .map(|date| date.to_timestamp().saturating_mul(1000))
        .unwrap_or_else(now_millis);
    let body_text = parsed
        .text_bodies()
        .map(|body| body.into_owned())
        .collect::<Vec<_>>()
        .join("\n");
    let body_html = parsed
        .html_bodies()
        .map(|body| body.into_owned())
        .collect::<Vec<_>>()
        .join("\n");
    let body_text = if body_text.trim().is_empty() {
        mail_parser::html_to_text(&body_html)
    } else {
        body_text
    };
    let attachments = parsed
        .attachments()
        .map(|part| {
            let content_type = part
                .content_type()
                .map(|content_type| {
                    format!(
                        "{}/{}",
                        content_type.ctype(),
                        content_type.subtype().unwrap_or("octet-stream")
                    )
                })
                .unwrap_or_else(|| "application/octet-stream".into());
            let data = part.decoded().into_owned();
            Attachment {
                filename: part.attachment_name().unwrap_or("attachment").to_string(),
                content_type,
                size: data.len() as u64,
                data,
            }
        })
        .collect::<Vec<_>>();

    let thread_id = references
        .first()
        .cloned()
        .or_else(|| in_reply_to.clone())
        .unwrap_or_else(|| message_id.clone());
    let thread_id = if thread_id.is_empty() {
        format!("subject:{}", crate::thread_subject(&subject))
    } else {
        thread_id
    };

    Ok(Message {
        account_id: account_id.into(),
        attachments,
        bcc,
        body_html: if body_html.trim().is_empty() {
            None
        } else {
            Some(body_html)
        },
        body_text,
        cc,
        date,
        flags: 0,
        from,
        id: id.into(),
        in_reply_to,
        mailbox: mailbox.into(),
        message_id,
        raw: raw.to_vec(),
        references,
        size: raw.len() as u64,
        subject,
        thread_id,
        to,
    })
}

fn convert_addresses(list: Option<&mail_parser::AddressList<'_>>) -> Vec<ModelAddress> {
    let Some(list) = list else {
        return Vec::new();
    };
    let mut result = Vec::new();
    for address in list.iter() {
        match address {
            Address::Mailbox(mailbox) => {
                if let Some(email) = mailbox.address() {
                    result.push(ModelAddress {
                        email: email.to_string(),
                        name: mailbox.name().map(str::to_string),
                    });
                }
            }
            Address::Group(group) => {
                for mailbox in group.mailboxes() {
                    if let Some(email) = mailbox.address() {
                        result.push(ModelAddress {
                            email: email.to_string(),
                            name: mailbox.name().map(str::to_string),
                        });
                    }
                }
            }
        }
    }
    result
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

    const RAW: &str = concat!(
        "From: Ann <ann@example.com>\r\n",
        "To: Bob <bob@example.com>\r\n",
        "Subject: Report\r\n",
        "Date: Tue, 25 Nov 2025 10:00:00 +0000\r\n",
        "Message-ID: <abc@example.com>\r\n",
        "Content-Type: multipart/mixed; boundary=\"b\"\r\n",
        "\r\n",
        "--b\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "See the attachment.\r\n",
        "--b\r\n",
        "Content-Type: application/pdf; name=report.pdf\r\n",
        "Content-Transfer-Encoding: base64\r\n",
        "\r\n",
        "JVBERi0xLjQK\r\n",
        "--b--\r\n",
    );

    #[test]
    fn parses_mime_message() {
        let message = parse_message(RAW.as_bytes(), "alice", "INBOX", "m1").unwrap();
        assert_eq!(message.subject, "Report");
        assert_eq!(message.from[0].email, "ann@example.com");
        assert_eq!(message.from[0].name.as_deref(), Some("Ann"));
        assert_eq!(message.to[0].email, "bob@example.com");
        assert!(message.body_text.contains("See the attachment."));
        assert_eq!(message.attachments.len(), 1);
        assert_eq!(message.attachments[0].filename, "report.pdf");
        assert_eq!(message.attachments[0].content_type, "application/pdf");
        assert_eq!(message.message_id, "abc@example.com");
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(
            parse_message(b"", "alice", "INBOX", "m1"),
            Err(MimeError::Empty)
        ));
    }
}
