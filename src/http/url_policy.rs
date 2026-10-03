//! Rules for URLs a server advertises: metadata, authorization, token,
//! registration and legacy SSE endpoint URLs.

use std::net::{Ipv4Addr, Ipv6Addr};

use url::{Host, Url};

use crate::config::validate::{MAX_URL_LEN, is_loopback};
use crate::error::{Error, ErrorKind};

/// The address class of a URL's host. Only IP literals and `localhost` are
/// classified; any other domain name counts as public.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostCategory {
    /// A domain name, or an IP address in none of the classes below.
    Public,
    /// `localhost`, `*.localhost`, a loopback or an unspecified address.
    Loopback,
    /// RFC 1918 IPv4 or unique-local IPv6.
    Private,
    /// Link-local IPv4 or IPv6, including cloud metadata addresses.
    LinkLocal,
}

/// Classifies the URL's host. IPv4-mapped IPv6 addresses are classified by
/// their IPv4 address.
#[must_use]
pub fn host_category(url: &Url) -> HostCategory {
    match url.host() {
        Some(Host::Domain(domain)) => domain_category(domain),
        Some(Host::Ipv4(ip)) => ipv4_category(ip),
        Some(Host::Ipv6(ip)) => ip
            .to_ipv4_mapped()
            .map_or_else(|| ipv6_category(ip), ipv4_category),
        None => HostCategory::Public,
    }
}

/// `url` lowercases the domains of `http` and `https` URLs.
fn domain_category(domain: &str) -> HostCategory {
    if domain == "localhost" || domain.ends_with(".localhost") {
        HostCategory::Loopback
    } else {
        HostCategory::Public
    }
}

fn ipv4_category(ip: Ipv4Addr) -> HostCategory {
    if ip.is_loopback() || ip.is_unspecified() {
        HostCategory::Loopback
    } else if ip.is_private() {
        HostCategory::Private
    } else if ip.is_link_local() {
        HostCategory::LinkLocal
    } else {
        HostCategory::Public
    }
}

fn ipv6_category(ip: Ipv6Addr) -> HostCategory {
    if ip.is_loopback() || ip.is_unspecified() {
        HostCategory::Loopback
    } else if ip.is_unique_local() {
        HostCategory::Private
    } else if ip.is_unicast_link_local() {
        HostCategory::LinkLocal
    } else {
        HostCategory::Public
    }
}

/// The URL rules for one configured server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlPolicy {
    server: Url,
}

impl UrlPolicy {
    /// The policy for `server`, a URL that passed
    /// [`parse_server_url`](crate::config::validate::parse_server_url), so it
    /// uses `http` only on a loopback host.
    #[must_use]
    pub const fn new(server: Url) -> Self {
        Self { server }
    }

    /// Checks a URL the server advertised. `role` names it in the error,
    /// such as "token endpoint".
    ///
    /// # Errors
    /// `url_rejected` naming the broken rule.
    pub fn check(&self, role: &str, url: &Url) -> Result<(), Error> {
        match self.violation(url) {
            Some(reason) => Err(rejected(role, reason)),
            None => Ok(()),
        }
    }

    /// Checks a legacy SSE `endpoint` URL, which must also be on the
    /// server's origin.
    ///
    /// # Errors
    /// `url_rejected` naming the broken rule.
    pub fn check_endpoint(&self, url: &Url) -> Result<(), Error> {
        const ROLE: &str = "SSE endpoint";
        self.check(ROLE, url)?;
        if url.origin() != self.server.origin() {
            return Err(rejected(ROLE, "it must be on the server's origin"));
        }
        Ok(())
    }

    /// Whether the server's credentials (its token and configured headers)
    /// may be sent to `url`: only on the configured server's origin.
    #[must_use]
    pub fn may_send_credentials(&self, url: &Url) -> bool {
        url.origin() == self.server.origin()
    }

    fn violation(&self, url: &Url) -> Option<&'static str> {
        if url.as_str().len() > MAX_URL_LEN {
            return Some("it is longer than 2048 bytes");
        }
        match url.scheme() {
            "https" => {}
            "http" if is_loopback(url) && self.server.scheme() == "http" => {}
            "http" => {
                return Some(
                    "use https; http is allowed only on loopback, for a server configured on loopback http",
                );
            }
            _ => return Some("use https"),
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Some("credentials in the URL are not allowed");
        }
        if url.fragment().is_some() {
            return Some("a fragment (#...) is not allowed");
        }
        let category = host_category(url);
        if category != HostCategory::Public && category != host_category(&self.server) {
            return Some(
                "it is a loopback, private or link-local address, and the configured server is not",
            );
        }
        None
    }
}

// The length reason in `violation` spells out this limit.
const _: () = assert!(MAX_URL_LEN == 2048);

fn rejected(role: &str, reason: &str) -> Error {
    Error::new(
        ErrorKind::UrlRejected,
        format!("{role} URL rejected: {reason}"),
    )
}
