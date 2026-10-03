//! Random values for one login: the PKCE verifier and challenge (RFC 7636)
//! and the `state` parameter.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use crate::error::{Error, ErrorKind};

/// Random bytes in a verifier or `state`: 256 bits.
const RANDOM_BYTES: usize = 32;

/// 32 random bytes, base64url without padding (43 characters).
///
/// # Errors
/// `network` if the OS has no randomness to give.
fn random_token() -> Result<String, Error> {
    let mut bytes = [0_u8; RANDOM_BYTES];
    getrandom::fill(&mut bytes)
        .map(|()| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(no_randomness)
}

/// The `state` and PKCE verifier of one login.
#[derive(Debug)]
pub(crate) struct Secrets {
    pub(crate) state: String,
    pub(crate) verifier: String,
}

/// A fresh `state` and verifier.
///
/// # Errors
/// `network` if the OS has no randomness to give.
pub(crate) fn secrets() -> Result<Secrets, Error> {
    random_token().and_then(|state| random_token().map(|verifier| Secrets { state, verifier }))
}

/// The S256 challenge for `verifier`.
pub(crate) fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn no_randomness(_cause: getrandom::Error) -> Error {
    Error::new(
        ErrorKind::Network,
        "the operating system gave no randomness for the login",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_random_and_url_safe() {
        let (one, two) = (random_token().unwrap(), random_token().unwrap());
        assert_ne!(one, two);
        assert_eq!(one.len(), 43);
        assert_eq!(URL_SAFE_NO_PAD.decode(&one).unwrap().len(), RANDOM_BYTES);
    }

    #[test]
    fn the_challenge_matches_rfc_7636_appendix_b() {
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn missing_randomness_is_reported() {
        let error = no_randomness(getrandom::Error::UNSUPPORTED);
        assert_eq!(error.kind(), ErrorKind::Network);
    }
}
