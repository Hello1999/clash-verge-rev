pub const RULES: &[&str] = &[
    "DOMAIN,localhost,DIRECT",
    "DOMAIN-SUFFIX,lan,DIRECT",
    "DOMAIN-SUFFIX,local,DIRECT",
    "DOMAIN-SUFFIX,home.arpa,DIRECT",
    "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
    "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
    "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
    "IP-CIDR6,::1/128,DIRECT,no-resolve",
    "IP-CIDR6,fc00::/7,DIRECT,no-resolve",
    "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
];

pub fn system_bypass(existing: &str) -> String {
    // Browser WFP filters allow loopback only; LAN requests must reach Clash first.
    let mut entries = vec!["localhost", "127.*", "[::1]"];
    for entry in existing.split(';').map(str::trim).filter(|entry| !entry.is_empty()) {
        let lower = entry.to_ascii_lowercase();
        let host = lower.trim_start_matches("http://").trim_start_matches("https://");
        // WinINet rejects an unbracketed IPv6 literal with ERROR_INVALID_PARAMETER.
        if host == "::1" {
            continue;
        }
        let lan = host == "<local>"
            || host == "*"
            || host.starts_with("10.")
            || host.starts_with("192.168.")
            || host.starts_with("169.254.")
            || (host.starts_with("172.")
                && host
                    .split('.')
                    .nth(1)
                    .and_then(|part| part.parse::<u8>().ok())
                    .is_some_and(|part| (16..=31).contains(&part)))
            || ["local", "lan", "home.arpa"]
                .iter()
                .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
            || (host.contains(':')
                && !matches!(host, "::1" | "[::1]")
                && (host.trim_start_matches('[').starts_with("fc")
                    || host.trim_start_matches('[').starts_with("fd")
                    || host.trim_start_matches('[').starts_with("fe80")));
        if !lan && !entries.iter().any(|saved| saved.eq_ignore_ascii_case(entry)) {
            entries.push(entry);
        }
    }
    entries.join(";")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_lan_bypass_is_removed_but_loopback_and_unrelated_exceptions_survive() {
        let bypass = system_bypass(
            "localhost;127.*;::1;192.168.*;192.168.5.1;10.*;172.16.*;172.31.*;<local>;*.local;*.lan;[fd00::1];8.134.107.154;*.steamcontent.com",
        );
        assert_eq!(bypass, "localhost;127.*;[::1];8.134.107.154;*.steamcontent.com");
        assert_eq!(system_bypass(&bypass), bypass);
    }
}
