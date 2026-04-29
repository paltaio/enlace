use std::net::{Ipv4Addr, Ipv6Addr};

use url::{Host, Url};

use crate::kdf::{NameError, validate_name};

pub fn validate_channel_name(name: &str) -> Result<(), NameError> {
    validate_name(name)
}

#[must_use]
pub fn host_is_public(url: &str) -> bool {
    let Ok(url) = Url::parse(url) else {
        return false;
    };
    if url.scheme() != "https" {
        return false;
    }
    match url.host() {
        Some(Host::Ipv4(ip)) => ipv4_is_public(ip),
        Some(Host::Ipv6(ip)) => ipv6_is_public(ip),
        Some(Host::Domain(_)) | None => false,
    }
}

fn ipv4_is_public(ip: Ipv4Addr) -> bool {
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast())
}

fn ipv6_is_public(ip: Ipv6Addr) -> bool {
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || ip.is_multicast()
        || is_ipv6_documentation(ip))
}

fn is_ipv6_documentation(ip: Ipv6Addr) -> bool {
    ip.segments()[0] == 0x2001 && ip.segments()[1] == 0x0db8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_channel_name_matches_kdf_rules() {
        assert!(validate_channel_name("alpha/1.ok").is_ok());
        assert_eq!(validate_channel_name("Alpha"), Err(NameError::InvalidChar));
    }

    #[test]
    fn public_https_ip_is_accepted() {
        assert!(host_is_public("https://8.8.8.8/relay"));
    }

    #[test]
    fn non_https_is_rejected() {
        assert!(!host_is_public("http://8.8.8.8/relay"));
    }

    #[test]
    fn private_and_loopback_hosts_are_rejected() {
        assert!(!host_is_public("https://127.0.0.1/relay"));
        assert!(!host_is_public("https://10.0.0.1/relay"));
        assert!(!host_is_public("https://[::1]/relay"));
        assert!(!host_is_public("https://[fc00::1]/relay"));
    }

    #[test]
    fn domain_hosts_are_rejected() {
        assert!(!host_is_public("https://example.com/relay"));
    }
}
