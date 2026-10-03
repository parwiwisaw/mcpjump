//! Validation of server names, server URLs and static headers.

use std::fmt;
use std::net::IpAddr;

use url::{Host, Url};

use crate::error::{Error, ErrorKind};
use crate::sys::env::Env;

/// Longest accepted server URL, in bytes.
pub const MAX_URL_LEN: usize = 2048;
/// Most static headers per server.
pub const MAX_HEADERS: usize = 32;
/// Longest header value, in bytes, before and after `${VAR}` expansion.
pub const MAX_HEADER_VALUE_LEN: usize = 8 * 1024;
/// Longest server name.
const MAX_NAME_LEN: usize = 64;
/// Longest header name.
const MAX_HEADER_NAME_LEN: usize = 256;
/// Header names mcpjump sets itself or that would break the transport.
const RESERVED_HEADERS: [&str; 6] = [
    "host",
    "content-type",
    "content-length",
    "transfer-encoding",
    "connection",
    "accept",
];

/// A validated server name: `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ServerName(String);

impl ServerName {
    /// Validates a server name.
    ///
    /// # Errors
    /// `invalid_name` if the name breaks the rule.
    pub fn parse(name: &str) -> Result<Self, Error> {
        let mut chars = name.chars();
        let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphanumeric());
        let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if first_ok && rest_ok && name.len() <= MAX_NAME_LEN {
            return Ok(Self(name.to_owned()));
        }
        Err(Error::new(
            ErrorKind::InvalidName,
            format!(
                "invalid server name {name:?}: use 1 to {MAX_NAME_LEN} letters, digits, '_' or '-', \
                 starting with a letter or digit"
            ),
        ))
    }

    /// The name as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ServerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Validates a server URL: at most 2048 bytes, `https` (or `http` for a
/// loopback host), no userinfo, no fragment.
///
/// # Errors
/// `invalid_url` naming the broken rule.
pub fn parse_server_url(raw: &str) -> Result<Url, Error> {
    let invalid =
        |reason: &str| Error::new(ErrorKind::InvalidUrl, format!("invalid URL: {reason}"));
    if raw.len() > MAX_URL_LEN {
        return Err(invalid(&format!("longer than {MAX_URL_LEN} bytes")));
    }
    let url = Url::parse(raw).map_err(|error| invalid(&error.to_string()))?;
    match url.scheme() {
        "https" => {}
        "http" if is_loopback(&url) => {}
        "http" => {
            return Err(invalid(
                "http is allowed only for loopback hosts; use https",
            ));
        }
        other => return Err(invalid(&format!("unsupported scheme {other:?}; use https"))),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid(
            "credentials in the URL are not allowed; use a header",
        ));
    }
    if url.fragment().is_some() {
        return Err(invalid("a fragment (#...) is not allowed"));
    }
    Ok(url)
}

/// Whether the URL's host is `localhost` or a loopback IP address.
#[must_use]
pub fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => IpAddr::V4(ip).is_loopback(),
        Some(Host::Ipv6(ip)) => IpAddr::V6(ip).is_loopback(),
        None => false,
    }
}

/// A static header whose value may reference environment variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderTemplate {
    name: String,
    raw_value: String,
    segments: Vec<Segment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Literal(String),
    Var {
        name: String,
        default: Option<String>,
    },
}

impl HeaderTemplate {
    /// Validates a header name and value template.
    ///
    /// # Errors
    /// `invalid_header` naming the broken rule.
    pub fn parse(name: &str, value: &str) -> Result<Self, Error> {
        check_header_name(name)?;
        check_header_value(name, value)?;
        let segments = parse_template(value)
            .map_err(|reason| invalid_header(name, &format!("bad variable reference: {reason}")))?;
        Ok(Self {
            name: name.to_owned(),
            raw_value: value.to_owned(),
            segments,
        })
    }

    /// Parses a `-H "Name: value"` argument.
    ///
    /// # Errors
    /// `invalid_header` if there is no `:` or the parts break the header rules.
    pub fn parse_arg(arg: &str) -> Result<Self, Error> {
        let Some((name, value)) = arg.split_once(':') else {
            return Err(Error::new(
                ErrorKind::InvalidHeader,
                "invalid header argument: expected \"Name: value\"",
            ));
        };
        Self::parse(name.trim(), value.trim())
    }

    /// The header name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The value as configured, before expansion.
    #[must_use]
    pub fn raw_value(&self) -> &str {
        &self.raw_value
    }

    /// Expands `${VAR}` and `${VAR:-default}` references.
    ///
    /// # Errors
    /// `missing_env_var` if a variable without a default is unset;
    /// `invalid_header` if the expanded value breaks the value rules.
    pub fn expand(&self, env: &dyn Env) -> Result<String, Error> {
        let mut value = String::new();
        for segment in &self.segments {
            match segment {
                Segment::Literal(text) => value.push_str(text),
                Segment::Var { name, default } => {
                    value.push_str(&lookup(env, &self.name, name, default.as_deref())?);
                }
            }
        }
        check_header_value(&self.name, &value)?;
        Ok(value)
    }
}

fn lookup(env: &dyn Env, header: &str, name: &str, default: Option<&str>) -> Result<String, Error> {
    match (env.var(name), default) {
        (Some(value), _) => Ok(value),
        (None, Some(default)) => Ok(default.to_owned()),
        (None, None) => Err(Error::new(
            ErrorKind::MissingEnvVar,
            format!("environment variable {name} (used by header {header}) is not set"),
        )),
    }
}

/// Checks a list of headers for count and case-insensitive duplicates.
///
/// # Errors
/// `invalid_header` if there are too many headers or a name repeats.
pub fn check_header_set(headers: &[HeaderTemplate]) -> Result<(), Error> {
    if headers.len() > MAX_HEADERS {
        return Err(Error::new(
            ErrorKind::InvalidHeader,
            format!("too many headers: at most {MAX_HEADERS}"),
        ));
    }
    for (index, header) in headers.iter().enumerate() {
        if headers[..index]
            .iter()
            .any(|earlier| earlier.name.eq_ignore_ascii_case(&header.name))
        {
            return Err(invalid_header(&header.name, "given more than once"));
        }
    }
    Ok(())
}

fn invalid_header(name: &str, reason: &str) -> Error {
    Error::new(
        ErrorKind::InvalidHeader,
        format!("invalid header {name:?}: {reason}"),
    )
}

fn check_header_name(name: &str) -> Result<(), Error> {
    if name.is_empty() || name.len() > MAX_HEADER_NAME_LEN || !name.bytes().all(is_token_byte) {
        // The name is not echoed: a malformed name is often a pasted secret.
        return Err(Error::new(
            ErrorKind::InvalidHeader,
            format!(
                "invalid header name: use 1 to {MAX_HEADER_NAME_LEN} letters, digits or !#$%&'*+-.^_`|~"
            ),
        ));
    }
    let lower = name.to_ascii_lowercase();
    if RESERVED_HEADERS.contains(&lower.as_str()) || lower.starts_with("mcp-") {
        return Err(invalid_header(
            name,
            "reserved; mcpjump sets this header itself",
        ));
    }
    Ok(())
}

/// RFC 9110 `tchar`.
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn check_header_value(name: &str, value: &str) -> Result<(), Error> {
    if value.len() > MAX_HEADER_VALUE_LEN {
        return Err(invalid_header(
            name,
            &format!("value longer than {MAX_HEADER_VALUE_LEN} bytes"),
        ));
    }
    if value.chars().any(|c| c.is_control() && c != '\t') {
        return Err(invalid_header(name, "value contains a control character"));
    }
    Ok(())
}

/// Splits a value into literal text and `${NAME}` or `${NAME:-default}`
/// references, where `NAME` is `[A-Z0-9_]+`. A `$` not followed by `{` is literal.
fn parse_template(value: &str) -> Result<Vec<Segment>, String> {
    let mut segments = Vec::new();
    let mut rest = value;
    while let Some(start) = rest.find("${") {
        push_literal(&mut segments, &rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find('}').ok_or("missing '}'")?;
        segments.push(parse_reference(&after[..end])?);
        rest = &after[end + 1..];
    }
    push_literal(&mut segments, rest);
    Ok(segments)
}

fn push_literal(segments: &mut Vec<Segment>, text: &str) {
    if !text.is_empty() {
        segments.push(Segment::Literal(text.to_owned()));
    }
}

fn parse_reference(reference: &str) -> Result<Segment, String> {
    let (name, default) = match reference.split_once(":-") {
        Some((name, default)) => (name, Some(default.to_owned())),
        None => (reference, None),
    };
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    if !valid {
        return Err(format!("{name:?} is not a variable name; use [A-Z0-9_]+"));
    }
    Ok(Segment::Var {
        name: name.to_owned(),
        default,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_splits_literals_and_references() {
        let segments = parse_template("Bearer ${TOKEN} and ${X:-d}$").unwrap();
        assert_eq!(
            segments,
            vec![
                Segment::Literal("Bearer ".into()),
                Segment::Var {
                    name: "TOKEN".into(),
                    default: None
                },
                Segment::Literal(" and ".into()),
                Segment::Var {
                    name: "X".into(),
                    default: Some("d".into())
                },
                Segment::Literal("$".into()),
            ]
        );
    }

    #[test]
    fn template_rejects_bad_references() {
        assert_eq!(parse_template("${OPEN"), Err("missing '}'".to_owned()));
        assert_eq!(
            parse_template("${lower}"),
            Err("\"lower\" is not a variable name; use [A-Z0-9_]+".to_owned())
        );
        assert_eq!(
            parse_template("${}"),
            Err("\"\" is not a variable name; use [A-Z0-9_]+".to_owned())
        );
    }
}
