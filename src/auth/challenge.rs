//! The `WWW-Authenticate: Bearer` challenge of a 401 or 403 (RFC 6750
//! section 3, RFC 9728 section 5.1).

use reqwest::StatusCode;
use reqwest::header::{HeaderMap, WWW_AUTHENTICATE};
use url::Url;

/// Longest `WWW-Authenticate` text parsed; a longer one counts as absent.
const MAX_HEADER_BYTES: usize = 8 * 1024;

/// Longest `scope` kept.
const MAX_SCOPE_BYTES: usize = 1024;

/// Longest `error` code kept.
const MAX_ERROR_BYTES: usize = 64;

/// What a server said when it refused a request. A missing or malformed
/// header leaves every parameter `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// The HTTP status: 401 or 403.
    pub status: u16,
    /// Where the protected resource metadata lives.
    pub resource_metadata: Option<Url>,
    /// The scope the request needs.
    pub scope: Option<String>,
    /// The OAuth error code, such as `invalid_token`.
    pub error: Option<String>,
}

impl Challenge {
    /// Parses the first `Bearer` challenge in `headers`.
    #[must_use]
    pub fn parse(status: StatusCode, headers: &HeaderMap) -> Self {
        let text = headers
            .get_all(WWW_AUTHENTICATE)
            .iter()
            .map(|value| value.to_str().unwrap_or("\u{1}"))
            .collect::<Vec<_>>()
            .join(", ");
        let params = (text.len() <= MAX_HEADER_BYTES)
            .then(|| lex(&text))
            .flatten()
            .and_then(|lexemes| bearer_params(&lexemes))
            .unwrap_or_default();
        let param = |name: &str| {
            params
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.clone())
        };
        Self {
            status: status.as_u16(),
            resource_metadata: param("resource_metadata").and_then(|url| Url::parse(&url).ok()),
            scope: param("scope").filter(|scope| scope.len() <= MAX_SCOPE_BYTES),
            error: param("error").filter(|error| is_error_code(error)),
        }
    }

    /// Whether this is a 403 asking for more scope (step-up).
    #[must_use]
    pub fn insufficient_scope(&self) -> bool {
        self.status == StatusCode::FORBIDDEN.as_u16()
            && self.error.as_deref() == Some("insufficient_scope")
    }

    /// Whether this is a 401: the credentials are missing, expired or revoked.
    #[must_use]
    pub fn unauthorized(&self) -> bool {
        self.status == StatusCode::UNAUTHORIZED.as_u16()
    }
}

/// An OAuth error code (RFC 6749 appendix A.7), short enough to show.
pub(crate) fn is_error_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= MAX_ERROR_BYTES
        && code
            .bytes()
            .all(|b| (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\')
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Lexeme {
    Token(String),
    Quoted(String),
    Equals,
    Comma,
}

/// Splits the header into tokens, quoted strings, `=` and `,`.
fn lex(text: &str) -> Option<Vec<Lexeme>> {
    let mut lexemes = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' => {}
            ',' => lexemes.push(Lexeme::Comma),
            '=' => lexemes.push(Lexeme::Equals),
            '"' => lexemes.push(Lexeme::Quoted(quoted(&mut chars)?)),
            c if is_tchar(c) => {
                let mut token = String::from(c);
                while let Some(next) = chars.next_if(|next| is_tchar(*next)) {
                    token.push(next);
                }
                lexemes.push(Lexeme::Token(token));
            }
            _ => return None,
        }
    }
    Some(lexemes)
}

/// The rest of a quoted string, after its opening quote.
fn quoted(chars: &mut impl Iterator<Item = char>) -> Option<String> {
    let mut value = String::new();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(value),
            '\\' => value.push(chars.next()?),
            c => value.push(c),
        }
    }
    None
}

/// RFC 9110 `tchar`.
fn is_tchar(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~/".contains(c)
}

/// The parameters of the `Bearer` challenges. A repeated parameter makes
/// the header ambiguous, so it counts as malformed.
fn bearer_params(lexemes: &[Lexeme]) -> Option<Vec<(String, String)>> {
    let mut params: Vec<(String, String)> = Vec::new();
    let mut in_bearer = false;
    let mut rest = lexemes;
    while !rest.is_empty() {
        rest = match rest {
            [
                Lexeme::Token(key),
                Lexeme::Equals,
                Lexeme::Token(value) | Lexeme::Quoted(value),
                tail @ ..,
            ] => {
                if params
                    .iter()
                    .any(|(seen, _)| seen.eq_ignore_ascii_case(key))
                {
                    return None;
                }
                if in_bearer {
                    params.push((key.clone(), value.clone()));
                }
                tail
            }
            [Lexeme::Token(scheme), tail @ ..] => {
                in_bearer = scheme.eq_ignore_ascii_case("bearer");
                tail
            }
            [Lexeme::Comma, tail @ ..] => tail,
            _ => return None,
        };
    }
    Some(params)
}

#[cfg(test)]
mod tests {
    use reqwest::header::HeaderValue;

    use super::*;

    fn parse(status: StatusCode, values: &[&[u8]]) -> Challenge {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(WWW_AUTHENTICATE, HeaderValue::from_bytes(value).unwrap());
        }
        Challenge::parse(status, &headers)
    }

    fn empty(status: u16) -> Challenge {
        Challenge {
            status,
            resource_metadata: None,
            scope: None,
            error: None,
        }
    }

    #[test]
    fn the_bearer_parameters_are_read() {
        let challenge = parse(
            StatusCode::FORBIDDEN,
            &[
                b"Basic realm=\"x\"",
                b"Bearer error=\"insufficient_scope\", scope=\"a b\", \
                  resource_metadata=\"https://mcp.example.com/.well-known/oauth-protected-resource\", realm=r",
            ],
        );
        assert_eq!(challenge.scope.as_deref(), Some("a b"));
        assert_eq!(
            challenge.resource_metadata.unwrap().path(),
            "/.well-known/oauth-protected-resource"
        );
        assert!(
            parse(StatusCode::FORBIDDEN, &[b"bearer error=insufficient_scope"])
                .insufficient_scope()
        );
        assert!(
            !parse(
                StatusCode::UNAUTHORIZED,
                &[b"Bearer error=insufficient_scope"]
            )
            .insufficient_scope()
        );
        assert!(!parse(StatusCode::FORBIDDEN, &[b"Bearer"]).insufficient_scope());
        assert!(parse(StatusCode::UNAUTHORIZED, &[]).unauthorized());
        assert!(!parse(StatusCode::FORBIDDEN, &[]).unauthorized());
    }

    #[test]
    fn quoted_strings_unescape() {
        let challenge = parse(StatusCode::UNAUTHORIZED, &[br#"Bearer scope="a\"b""#]);
        assert_eq!(challenge.scope.as_deref(), Some("a\"b"));
    }

    #[test]
    fn other_schemes_parameters_are_ignored() {
        let challenge = parse(StatusCode::UNAUTHORIZED, &[b"DPoP scope=x, Bearer"]);
        assert_eq!(challenge, empty(401));
    }

    #[test]
    fn a_malformed_or_oversized_header_has_no_parameters() {
        let long = format!("Bearer scope=\"{}\"", "a".repeat(MAX_HEADER_BYTES));
        let cases: [&[u8]; 9] = [
            b"Bearer scope=\"unterminated",
            b"Bearer scope=\"bad escape\\",
            b"Bearer scope=a, scope=b",
            b"Bearer scope==",
            b"Bearer @",
            br#"Bearer error="a\\b""#,
            b"Bearer resource_metadata=\"not a url\"",
            b"Bearer scope=\xff",
            long.as_bytes(),
        ];
        for case in cases {
            assert_eq!(parse(StatusCode::UNAUTHORIZED, &[case]), empty(401));
        }
    }

    #[test]
    fn oversized_parameters_are_dropped() {
        let scope = format!("Bearer scope=\"{}\"", "s".repeat(MAX_SCOPE_BYTES + 1));
        assert_eq!(
            parse(StatusCode::UNAUTHORIZED, &[scope.as_bytes()]).scope,
            None
        );
        let error = format!("Bearer error={}", "e".repeat(MAX_ERROR_BYTES + 1));
        assert_eq!(
            parse(StatusCode::UNAUTHORIZED, &[error.as_bytes()]).error,
            None
        );
        assert!(!is_error_code(""));
        assert!(!is_error_code("a\u{1}"));
    }
}
