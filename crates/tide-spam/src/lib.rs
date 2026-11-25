use std::net::{IpAddr, ToSocketAddrs};
use std::process::Command;

pub struct SpamContext<'a> {
    pub peer: IpAddr,
    pub helo: &'a str,
    pub mail_from: &'a str,
    pub raw: &'a [u8],
    pub subject: String,
    pub body: String,
    pub html: String,
    pub spf_fail: bool,
    pub dkim_fail: bool,
    pub dmarc_fail: bool,
}

impl<'a> SpamContext<'a> {
    pub fn new(
        peer: IpAddr,
        helo: &'a str,
        mail_from: &'a str,
        raw: &'a [u8],
        spf_fail: bool,
        dkim_fail: bool,
        dmarc_fail: bool,
    ) -> Self {
        let parsed = mail_parser::MessageParser::new().parse(raw);
        let subject = parsed
            .as_ref()
            .and_then(|message| message.subject())
            .unwrap_or_default()
            .to_string();
        let body = parsed
            .as_ref()
            .map(|message| {
                message
                    .text_bodies()
                    .map(|body| body.into_owned())
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        let html = parsed
            .as_ref()
            .map(|message| {
                message
                    .html_bodies()
                    .map(|body| body.into_owned())
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        Self {
            peer,
            helo,
            mail_from,
            raw,
            subject,
            body,
            html,
            spf_fail,
            dkim_fail,
            dmarc_fail,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SpamVerdict {
    pub score: f32,
    pub rules: Vec<String>,
    pub reject: bool,
}

impl SpamVerdict {
    pub fn add(&mut self, score: f32, rule: impl Into<String>) {
        self.score += score;
        self.rules.push(rule.into());
    }
}

pub trait SpamFilter: Send + Sync {
    fn name(&self) -> &'static str;
    fn check(&self, context: &SpamContext<'_>) -> SpamVerdict;
}

#[derive(Debug, Default)]
pub struct RuleFilter;

impl SpamFilter for RuleFilter {
    fn name(&self) -> &'static str {
        "rules"
    }

    fn check(&self, context: &SpamContext<'_>) -> SpamVerdict {
        let mut verdict = SpamVerdict::default();
        if context.spf_fail {
            verdict.add(2.0, "spf_fail");
        }
        if context.dkim_fail {
            verdict.add(1.5, "dkim_fail");
        }
        if context.dmarc_fail {
            verdict.add(2.0, "dmarc_fail");
        }
        let subject = context.subject.to_ascii_lowercase();
        let body = context.body.to_ascii_lowercase();
        let combined = format!("{subject}\n{body}");
        for word in [
            "viagra",
            "casino",
            "lottery",
            "crypto giveaway",
            "wire transfer",
            "click here to claim",
            "act now",
            "limited offer",
            "unsecured loan",
        ] {
            if combined.contains(word) {
                verdict.add(1.0, format!("keyword:{word}"));
            }
        }
        let letters = subject.chars().filter(|ch| ch.is_alphabetic()).count();
        let uppercase = subject.chars().filter(|ch| ch.is_uppercase()).count();
        if letters >= 8 && uppercase * 100 / letters >= 70 {
            verdict.add(1.0, "subject_all_caps");
        }
        let links = body.matches("http://").count() + body.matches("https://").count();
        if links >= 10 {
            verdict.add(1.0, "many_links");
        }
        if context.body.trim().is_empty() && !context.html.trim().is_empty() {
            verdict.add(0.5, "html_only");
        }
        if context.mail_from.is_empty() {
            verdict.add(0.5, "null_sender");
        }
        if context.raw.len() > 10 * 1024 * 1024 {
            verdict.add(0.5, "large_message");
        }
        verdict
    }
}

#[derive(Debug, Default)]
pub struct DnsblFilter {
    pub zones: Vec<String>,
}

impl DnsblFilter {
    pub fn new(zones: Vec<String>) -> Self {
        Self { zones }
    }
}

impl SpamFilter for DnsblFilter {
    fn name(&self) -> &'static str {
        "dnsbl"
    }

    fn check(&self, context: &SpamContext<'_>) -> SpamVerdict {
        let mut verdict = SpamVerdict::default();
        if context.peer.is_loopback() {
            return verdict;
        }
        let ip = context.peer.to_string();
        let reversed = ip.split('.').rev().collect::<Vec<_>>().join(".");
        for zone in &self.zones {
            let query = format!("{reversed}.{zone}:0");
            if query
                .as_str()
                .to_socket_addrs()
                .map(|mut addresses| addresses.next().is_some())
                .unwrap_or(false)
            {
                verdict.add(5.0, format!("dnsbl:{zone}"));
            }
        }
        verdict
    }
}

#[derive(Debug, Default)]
pub struct ExternalFilter {
    pub command: String,
}

impl ExternalFilter {
    pub fn new(command: String) -> Self {
        Self { command }
    }
}

impl SpamFilter for ExternalFilter {
    fn name(&self) -> &'static str {
        "external"
    }

    fn check(&self, context: &SpamContext<'_>) -> SpamVerdict {
        let mut verdict = SpamVerdict::default();
        let mut parts = self.command.split_whitespace();
        let Some(program) = parts.next() else {
            return verdict;
        };
        let mut command = Command::new(program);
        command.args(parts);
        command.arg("-");
        command.stdin(std::process::Stdio::piped());
        command.stdout(std::process::Stdio::piped());
        command.stderr(std::process::Stdio::null());
        let Ok(mut child) = command.spawn() else {
            return verdict;
        };
        if let Some(stdin) = child.stdin.as_mut() {
            use std::io::Write;
            let _ = stdin.write_all(context.raw);
        }
        let Ok(output) = child.wait_with_output() else {
            return verdict;
        };
        let text = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
        if text.contains("x-spam-flag: yes") {
            verdict.add(5.0, "external:spamassassin");
        }
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("x-spam-score:") {
                if let Ok(score) = value.trim().parse::<f32>() {
                    verdict.add(score, "external:score");
                }
            }
        }
        verdict
    }
}

pub struct SpamEngine {
    filters: Vec<Box<dyn SpamFilter>>,
    threshold: f32,
    reject_threshold: f32,
}

impl SpamEngine {
    pub fn new(filters: Vec<Box<dyn SpamFilter>>, threshold: f32, reject_threshold: f32) -> Self {
        Self {
            filters,
            threshold,
            reject_threshold,
        }
    }

    pub fn check(&self, context: &SpamContext<'_>) -> SpamVerdict {
        let mut result = SpamVerdict::default();
        for filter in &self.filters {
            let verdict = filter.check(context);
            if !verdict.rules.is_empty() {
                result.rules.extend(
                    verdict
                        .rules
                        .into_iter()
                        .map(|rule| format!("{}:{}", filter.name(), rule)),
                );
            }
            result.score += verdict.score;
        }
        result.score = result.score.max(0.0);
        result.reject = result.score >= self.reject_threshold;
        result
    }

    pub fn is_spam(&self, verdict: &SpamVerdict) -> bool {
        verdict.score >= self.threshold
    }

    pub fn threshold(&self) -> f32 {
        self.threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn context(subject: &str, body: &str) -> SpamContext<'static> {
        let raw: &'static [u8] = Box::leak(
            format!("From: a@example.com\r\nSubject: {subject}\r\n\r\n{body}")
                .into_bytes()
                .into_boxed_slice(),
        );
        SpamContext::new(
            "203.0.113.10".parse::<IpAddr>().unwrap(),
            "client",
            "a@example.com",
            raw,
            false,
            false,
            false,
        )
    }

    #[test]
    fn rules_score_spam_words() {
        let filter = RuleFilter;
        let verdict = filter.check(&context("WINNER", "click here to claim your prize"));
        assert!(verdict.score >= 1.0);
        assert!(
            verdict
                .rules
                .iter()
                .any(|rule| rule.starts_with("keyword:"))
        );
    }

    #[test]
    fn rules_penalize_auth_failures() {
        let raw = b"From: a@example.com\r\nSubject: hi\r\n\r\nbody";
        let context = SpamContext::new(
            "203.0.113.10".parse().unwrap(),
            "client",
            "",
            raw,
            true,
            true,
            true,
        );
        let verdict = RuleFilter.check(&context);
        assert!(verdict.score >= 5.0);
    }

    #[test]
    fn engine_combines_filters() {
        let engine = SpamEngine::new(
            vec![Box::new(RuleFilter), Box::new(DnsblFilter::default())],
            2.0,
            5.0,
        );
        let verdict = engine.check(&context("hi", "hello"));
        assert!(!verdict.reject);
        assert_eq!(engine.threshold(), 2.0);
    }
}
