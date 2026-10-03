//! A redirect URL pasted into the terminal, for a browser on another
//! machine. It gets the listener's checks plus an exact match on the
//! redirect URI.

use tokio::sync::mpsc::{Receiver, Sender};
use url::Url;

use crate::auth::callback::{Verdict, check_params};

/// Pasted lines read in one login.
pub(crate) const MAX_PASTES: usize = 16;

/// Checks one pasted line against the pending login.
pub(crate) fn check_pasted(line: &str, redirect_uri: &Url, state: &str) -> Verdict {
    let url = Url::parse(line).map_err(|_| "it is not a URL")?;
    let same_target = url.scheme() == redirect_uri.scheme()
        && url.host_str() == redirect_uri.host_str()
        && url.port() == redirect_uri.port()
        && url.path() == redirect_uri.path();
    if !same_target || !url.username().is_empty() || url.password().is_some() {
        return Err("it is not this login's redirect URL");
    }
    if url.fragment().is_some() {
        return Err("it has a fragment");
    }
    check_params(url.query().unwrap_or_default(), state)
}

/// Checks each pasted line and sends its verdict, rejected ones included,
/// so the login can say why a paste was ignored.
pub(crate) async fn forward(
    mut lines: Receiver<String>,
    redirect_uri: Url,
    state: String,
    verdicts: Sender<Verdict>,
) {
    for _ in 0..=MAX_PASTES {
        let Some(line) = lines.recv().await else {
            return;
        };
        let _login_may_be_over = verdicts
            .send(check_pasted(&line, &redirect_uri, &state))
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::callback::Callback;

    fn check(line: &str) -> Verdict {
        let redirect = Url::parse("http://127.0.0.1:5000/callback").unwrap();
        check_pasted(line, &redirect, "s1")
    }

    #[test]
    fn the_exact_redirect_url_is_accepted() {
        assert_eq!(
            check("http://127.0.0.1:5000/callback?code=c&state=s1"),
            Ok(Callback::Code {
                code: "c".into(),
                iss: None
            })
        );
    }

    #[test]
    fn any_other_url_is_rejected() {
        for line in [
            "not a url",
            "https://127.0.0.1:5000/callback?code=c&state=s1",
            "http://localhost:5000/callback?code=c&state=s1",
            "http://127.0.0.1:5001/callback?code=c&state=s1",
            "http://127.0.0.1:5000/other?code=c&state=s1",
            "http://user@127.0.0.1:5000/callback?code=c&state=s1",
            "http://:pw@127.0.0.1:5000/callback?code=c&state=s1",
            "http://127.0.0.1:5000/callback?code=c&state=s1#frag",
            "http://127.0.0.1:5000/callback",
        ] {
            assert!(check(line).is_err(), "{line}");
        }
    }

    #[tokio::test]
    async fn the_forwarder_stops_when_the_input_ends() {
        let (lines, input) = tokio::sync::mpsc::channel(1);
        drop(lines);
        let (verdicts, mut received) = tokio::sync::mpsc::channel(1);
        let redirect = Url::parse("http://127.0.0.1:5000/callback").unwrap();
        forward(input, redirect, "s1".into(), verdicts).await;
        assert!(received.recv().await.is_none());
    }
}
