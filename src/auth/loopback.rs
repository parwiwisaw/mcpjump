//! The loopback redirect listener (RFC 8252 section 7.3). It answers only
//! `GET /callback` with the exact `Host`, never logs the query, and hands
//! each response that carries the right `state` to the login.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::sync::mpsc::Sender;
use tokio::time::timeout;
use url::Url;

use crate::auth::callback::{Verdict, check_params};
use crate::error::{Error, ErrorKind};

/// Connections served at once; more wait for a slot.
const MAX_ACTIVE: usize = 4;

/// Connections served in one login.
const MAX_CONNECTIONS: usize = 256;

/// Longest request head read.
const MAX_HEAD_BYTES: usize = 8 * 1024;

/// Most request headers parsed.
const MAX_HEADERS: usize = 32;

/// Time a connection has to send its request head.
const HEAD_DEADLINE: Duration = Duration::from_secs(5);

const DONE_PAGE: &str = "<!doctype html><title>mcpjump</title><p>mcpjump received the authorization response. You can close this tab.</p>";
const BAD_PAGE: &str =
    "<!doctype html><title>mcpjump</title><p>This is not a valid authorization response.</p>";

/// A bound callback listener and its redirect URI.
#[derive(Debug)]
pub(crate) struct Listener {
    pub(crate) socket: TcpListener,
    pub(crate) port: u16,
    pub(crate) redirect_uri: Url,
}

/// Binds `127.0.0.1:<port>`; port 0 picks a free one.
///
/// # Errors
/// `network` if the port is taken or binding fails.
pub(crate) async fn listen(port: u16) -> Result<Listener, Error> {
    TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .await
        .and_then(|socket| socket.local_addr().map(|address| (socket, address.port())))
        .ok()
        .and_then(|(socket, port)| {
            Url::parse(&format!("http://127.0.0.1:{port}/callback"))
                .ok()
                .map(|redirect_uri| Listener {
                    socket,
                    port,
                    redirect_uri,
                })
        })
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Network,
                format!("cannot listen for the login callback on 127.0.0.1:{port}"),
            )
        })
}

/// Serves callbacks on `listener` until the login drops `verdicts` or
/// [`MAX_CONNECTIONS`] have been served.
pub(crate) async fn serve(
    listener: TcpListener,
    port: u16,
    state: String,
    verdicts: Sender<Verdict>,
) {
    let slots = Arc::new(Semaphore::new(MAX_ACTIVE));
    let state: Arc<str> = state.into();
    for _ in 0..MAX_CONNECTIONS {
        let accepted = listener.accept().await.ok();
        let slot = Arc::clone(&slots).acquire_owned().await.ok();
        accepted
            .zip(slot)
            .into_iter()
            .for_each(|((stream, _), slot)| {
                let (state, verdicts) = (Arc::clone(&state), verdicts.clone());
                tokio::spawn(async move {
                    answer(stream, port, &state, &verdicts).await;
                    drop(slot);
                });
            });
    }
}

async fn answer(mut stream: TcpStream, port: u16, state: &str, verdicts: &Sender<Verdict>) {
    let head = timeout(HEAD_DEADLINE, read_head(&mut stream))
        .await
        .ok()
        .flatten();
    let verdict = head
        .as_deref()
        .and_then(|head| query_of(head, port))
        .map(|query| check_params(&query, state));
    let page = match &verdict {
        Some(Ok(_)) => ("200 OK", DONE_PAGE),
        _ => ("400 Bad Request", BAD_PAGE),
    };
    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{}",
        page.0,
        page.1.len(),
        page.1
    );
    let _peer_may_be_gone = stream.write_all(response.as_bytes()).await;
    let _peer_may_be_gone = stream.shutdown().await;
    if let Some(Ok(callback)) = verdict {
        let _login_may_be_over = verdicts.send(Ok(callback)).await;
    }
}

/// Reads up to the blank line ending the head. `None` on end of input, a
/// read error, or a head over [`MAX_HEAD_BYTES`].
async fn read_head(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut head = Vec::with_capacity(1024);
    let mut buffer = [0_u8; 1024];
    while head.len() <= MAX_HEAD_BYTES && !ends_head(&head) {
        let read = stream
            .read(&mut buffer)
            .await
            .ok()
            .filter(|read| *read > 0)?;
        head.extend(buffer.iter().take(read));
    }
    ends_head(&head).then_some(head)
}

fn ends_head(head: &[u8]) -> bool {
    head.windows(4).any(|window| window == b"\r\n\r\n")
}

/// The query of a `GET /callback` sent to `127.0.0.1:<port>`.
fn query_of(head: &[u8], port: u16) -> Option<String> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    let complete = request.parse(head).is_ok_and(|status| status.is_complete());
    let host = format!("127.0.0.1:{port}");
    let one_host = request
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("host"))
        .map(|header| header.value)
        .eq([host.as_bytes()]);
    request
        .path
        .filter(|_| complete && one_host && request.method == Some("GET"))
        .map(|target| target.split_once('?').unwrap_or((target, "")))
        .filter(|(path, _)| *path == "/callback")
        .map(|(_, query)| query.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(text: &str) -> Vec<u8> {
        text.replace('\n', "\r\n").into_bytes()
    }

    #[test]
    fn only_a_get_of_the_callback_on_the_exact_host_is_read() {
        let good = head("GET /callback?code=a&state=b HTTP/1.1\nHost: 127.0.0.1:5000\n\n");
        assert_eq!(query_of(&good, 5000).as_deref(), Some("code=a&state=b"));
        let bare = head("GET /callback HTTP/1.1\nHost: 127.0.0.1:5000\n\n");
        assert_eq!(query_of(&bare, 5000).as_deref(), Some(""));
        for bad in [
            "POST /callback?code=a HTTP/1.1\nHost: 127.0.0.1:5000\n\n",
            "GET /other?code=a HTTP/1.1\nHost: 127.0.0.1:5000\n\n",
            "GET /callback?code=a HTTP/1.1\nHost: localhost:5000\n\n",
            "GET /callback?code=a HTTP/1.1\nHost: 127.0.0.1:5001\n\n",
            "GET /callback?code=a HTTP/1.1\n\n",
            "GET /callback?code=a HTTP/1.1\nHost: 127.0.0.1:5000\nHost: 127.0.0.1:5000\n\n",
            "GET /callback?code=a HTTP/1.1\nBad Header\n\n",
            "GET /callback?code=a HTTP/1.1\nHost: 127.0.0.1:5000\n",
        ] {
            assert_eq!(query_of(&head(bad), 5000), None, "{bad}");
        }
    }

    #[tokio::test]
    async fn the_listener_serves_a_bounded_number_of_connections() {
        let listener = listen(0).await.unwrap();
        assert_eq!(
            listener.redirect_uri.as_str(),
            format!("http://127.0.0.1:{}/callback", listener.port)
        );
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let server = tokio::spawn(serve(listener.socket, listener.port, "s".into(), sender));
        for served in 0..MAX_CONNECTIONS {
            let mut stream = TcpStream::connect(("127.0.0.1", listener.port))
                .await
                .unwrap();
            if served == 0 {
                stream.write_all(b"GET /").await.unwrap();
                stream.shutdown().await.unwrap();
            } else if served == 1 {
                let long = vec![b'a'; MAX_HEAD_BYTES + 1];
                stream.write_all(&long).await.unwrap();
            } else {
                stream.write_all(b"x\r\n\r\n").await.unwrap();
            }
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await.unwrap();
            assert!(reply.starts_with(b"HTTP/1.1 400"));
        }
        server.await.unwrap();
    }
}
