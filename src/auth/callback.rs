//! The authorization response's query parameters (RFC 6749 section 4.1.2),
//! checked the same way whether they came to the loopback listener or in a
//! pasted URL.

use url::form_urlencoded;

use crate::auth::challenge::is_error_code;

/// Most parameters one response may carry.
const MAX_PARAMS: usize = 32;

/// Longest authorization code accepted.
const MAX_CODE_BYTES: usize = 4096;

/// Longest `iss` accepted.
const MAX_ISS_BYTES: usize = 2048;

/// A response that carries the right `state`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Callback {
    /// The user approved: the code, and the issuer if the server sent it.
    Code { code: String, iss: Option<String> },
    /// The server refused with this OAuth error code.
    Denied(String),
}

/// A checked response, or why it was rejected. The reason never repeats
/// the query, which may hold a code.
pub(crate) type Verdict = Result<Callback, &'static str>;

/// Checks `query` against the pending login's `state`. Unknown parameters
/// are ignored.
pub(crate) fn check_params(query: &str, state: &str) -> Verdict {
    let params: Vec<(String, String)> = form_urlencoded::parse(query.as_bytes())
        .take(MAX_PARAMS + 1)
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    if params.len() > MAX_PARAMS {
        return Err("too many parameters");
    }
    let mut keys: Vec<&str> = params.iter().map(|(key, _)| key.as_str()).collect();
    keys.sort_unstable();
    if keys.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("a parameter appears twice");
    }
    let param = |name: &str| {
        params
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    if !param("state").is_some_and(|sent| same(sent.as_bytes(), state.as_bytes())) {
        return Err("the state does not match this login");
    }
    match (param("code"), param("error")) {
        (Some(code), None) => code_of(code, param("iss")),
        (None, Some(error)) if is_error_code(error) => Ok(Callback::Denied(error.to_owned())),
        (None, Some(_)) => Err("the error code is malformed"),
        _ => Err("expected exactly one of code or error"),
    }
}

fn code_of(code: &str, iss: Option<&str>) -> Verdict {
    if code.is_empty() || code.len() > MAX_CODE_BYTES || !code.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err("the code is malformed");
    }
    if iss.is_some_and(|iss| iss.len() > MAX_ISS_BYTES) {
        return Err("the iss parameter is too long");
    }
    Ok(Callback::Code {
        code: code.to_owned(),
        iss: iss.map(str::to_owned),
    })
}

/// Compares in time that depends only on the lengths, so a guess at
/// `state` learns nothing from how long the check took.
fn same(sent: &[u8], expected: &[u8]) -> bool {
    sent.len() == expected.len()
        && sent
            .iter()
            .zip(expected)
            .fold(0, |diff, (a, b)| diff | (a ^ b))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATE: &str = "s123";

    #[test]
    fn a_code_with_the_right_state_is_accepted() {
        assert_eq!(
            check_params("code=abc&state=s123&iss=https%3A%2F%2Fa.example", STATE),
            Ok(Callback::Code {
                code: "abc".into(),
                iss: Some("https://a.example".into())
            })
        );
        assert_eq!(
            check_params("state=s123&code=abc&extra=1", STATE),
            Ok(Callback::Code {
                code: "abc".into(),
                iss: None
            })
        );
    }

    #[test]
    fn an_error_with_the_right_state_is_a_denial() {
        assert_eq!(
            check_params("error=access_denied&state=s123", STATE),
            Ok(Callback::Denied("access_denied".into()))
        );
    }

    #[test]
    fn every_broken_rule_is_rejected() {
        let many = (0..33)
            .map(|i| format!("k{i}=v"))
            .collect::<Vec<_>>()
            .join("&");
        let long_code = format!("code={}&state=s123", "a".repeat(4097));
        let long_iss = format!("code=a&state=s123&iss={}", "a".repeat(2049));
        let cases = [
            many.as_str(),
            "code=a&code=b&state=s123",
            "code=a",
            "code=a&state=s124",
            "code=a&state=s12",
            "code=a&error=x&state=s123",
            "state=s123",
            "error=bad%22code&state=s123",
            "code=&state=s123",
            "code=a%20b&state=s123",
            long_code.as_str(),
            long_iss.as_str(),
        ];
        for case in cases {
            assert!(check_params(case, STATE).is_err(), "{case}");
        }
    }
}
