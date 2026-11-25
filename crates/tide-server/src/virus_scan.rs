use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::config::AntivirusSettings;

pub struct VirusScanner {
    settings: AntivirusSettings,
}

impl VirusScanner {
    pub fn new(settings: AntivirusSettings) -> Self {
        Self { settings }
    }

    pub fn scan(&self, raw: &[u8]) -> Result<(), String> {
        if !self.settings.enabled {
            return Ok(());
        }
        if let Some(address) = &self.settings.clamav_addr {
            scan_clamav(address, raw)?;
        }
        if let Some(command) = &self.settings.command {
            scan_command(command, raw)?;
        }
        Ok(())
    }
}

fn scan_clamav(address: &str, raw: &[u8]) -> Result<(), String> {
    let mut stream = TcpStream::connect(address).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|error| error.to_string())?;
    stream
        .write_all(b"zINSTREAM\0")
        .map_err(|error| error.to_string())?;
    for chunk in raw.chunks(64 * 1024) {
        let length = u32::try_from(chunk.len()).map_err(|_| "chunk too large")?;
        stream
            .write_all(&length.to_be_bytes())
            .map_err(|error| error.to_string())?;
        stream.write_all(chunk).map_err(|error| error.to_string())?;
    }
    stream
        .write_all(&0u32.to_be_bytes())
        .map_err(|error| error.to_string())?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|error| error.to_string())?;
    if response.contains("FOUND") {
        return Err(format!("infected: {}", response.trim()));
    }
    if response.contains("OK") {
        Ok(())
    } else {
        Err(format!("unexpected clamav response: {}", response.trim()))
    }
}

fn scan_command(command: &str, raw: &[u8]) -> Result<(), String> {
    let mut parts = command.split_whitespace();
    let program = parts.next().ok_or("empty antivirus command")?;
    let mut child = Command::new(program)
        .args(parts)
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| error.to_string())?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(raw).map_err(|error| error.to_string())?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| error.to_string())?;
    let text = String::from_utf8_lossy(&output.stdout);
    if text.contains("FOUND") || !output.status.success() {
        return Err(format!("infected: {}", text.trim()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_scanner_is_noop() {
        let scanner = VirusScanner::new(AntivirusSettings::default());
        assert!(scanner.scan(b"data").is_ok());
    }
}
