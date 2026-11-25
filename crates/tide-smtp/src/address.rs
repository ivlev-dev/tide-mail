use std::net::{Ipv4Addr, Ipv6Addr};

pub fn validate_address(address: &str, smtputf8: bool) -> Result<String, String> {
    let address = strip_source_route(address);
    if address.is_empty() || address == "<>" {
        return Ok(String::new());
    }
    if address.len() > 254 {
        return Err("address is too long".into());
    }
    let Some((local, domain)) = address.rsplit_once('@') else {
        return Err("address must contain @".into());
    };
    if local.is_empty() || local.len() > 64 {
        return Err("invalid local part length".into());
    }
    if !smtputf8 && !local.is_ascii() {
        return Err("SMTPUTF8 is required for the local part".into());
    }
    let quoted = local.starts_with('"') && local.ends_with('"') && local.len() >= 2;
    if !quoted
        && local
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err("invalid character in local part".into());
    }
    if quoted {
        let inner = &local[1..local.len() - 1];
        if inner
            .chars()
            .any(|ch| ch.is_control() || ch == '\n' || ch == '\r')
        {
            return Err("invalid character in quoted local part".into());
        }
    }
    let domain = normalize_domain(domain, smtputf8)?;
    Ok(format!("{local}@{domain}"))
}

fn strip_source_route(address: &str) -> String {
    let address = address.trim();
    if address.starts_with('@') {
        if let Some((_, rest)) = address.rsplit_once(':') {
            return rest.to_string();
        }
    }
    address.to_string()
}

fn normalize_domain(domain: &str, smtputf8: bool) -> Result<String, String> {
    let domain = domain.trim_end_matches('.');
    if let Some(literal) = domain
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    {
        if let Some(ipv6) = literal.strip_prefix("IPv6:") {
            ipv6.parse::<Ipv6Addr>()
                .map_err(|_| "invalid IPv6 address literal")?;
            return Ok(format!("[IPv6:{ipv6}]"));
        }
        literal
            .parse::<Ipv4Addr>()
            .map_err(|_| "invalid IPv4 address literal")?;
        return Ok(format!("[{literal}]"));
    }
    if !smtputf8 && !domain.is_ascii() {
        return Err("SMTPUTF8 is required for the domain".into());
    }
    let ascii = idna::domain_to_ascii(domain).map_err(|_| "invalid IDNA domain")?;
    if ascii.is_empty() || ascii.len() > 253 {
        return Err("invalid domain length".into());
    }
    if ascii
        .split('.')
        .any(|label| label.is_empty() || label.len() > 63)
    {
        return Err("invalid domain label".into());
    }
    Ok(ascii)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_idna_and_literals() {
        assert_eq!(
            validate_address("user@пример.рф", true).unwrap(),
            "user@xn--e1afmkfd.xn--p1ai"
        );
        assert!(validate_address("user@пример.рф", false).is_err());
        assert_eq!(
            validate_address("user@[127.0.0.1]", false).unwrap(),
            "user@[127.0.0.1]"
        );
        assert!(validate_address("user@[999.1.1.1]", false).is_err());
        assert_eq!(
            validate_address("@a,@b:user@example.com", false).unwrap(),
            "user@example.com"
        );
    }

    #[test]
    fn accepts_quoted_local_part_and_fqdn() {
        assert_eq!(
            validate_address("\"a b\"@example.com.", false).unwrap(),
            "\"a b\"@example.com"
        );
        assert_eq!(validate_address("<>", false).unwrap(), "");
    }

    #[test]
    fn rejects_broken_addresses() {
        assert!(validate_address("user", false).is_err());
        assert!(validate_address("@example.com", false).is_err());
        assert!(validate_address("user@", false).is_err());
    }
}
