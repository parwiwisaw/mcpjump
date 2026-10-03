//! A user watching stderr. When a login prints its URL as a JSON notice,
//! they open it in a browser of their own, or on another machine whose
//! redirect they paste back into the terminal.

use std::io::{self, Write};
use std::net::TcpStream;
use std::thread;

use serde_json::Value;
use tokio::sync::mpsc::Sender;
use url::Url;

use crate::support::fakes::browser::follow;

/// What the user does with the printed URL.
#[derive(Debug)]
pub(crate) enum Act {
    /// Nothing.
    Wait,
    /// Opens it in a browser on this machine.
    Open,
    /// Opens it elsewhere and pastes the redirect it ends on.
    Paste(Sender<String>),
    /// Connects to the callback port and hangs up, again and again, until
    /// the listener stops taking connections.
    Hangup,
}

/// A stderr writer that keeps the text and acts on the login URL.
#[derive(Debug)]
pub(crate) struct User {
    act: Act,
    text: Vec<u8>,
    read: usize,
}

impl User {
    pub(crate) fn new(act: Act) -> Self {
        Self {
            act,
            text: Vec::new(),
            read: 0,
        }
    }

    /// Everything written so far.
    pub(crate) fn text(&self) -> String {
        String::from_utf8(self.text.clone()).unwrap()
    }

    fn see(&self, line: &str) {
        let Some(url) = serde_json::from_str::<Value>(line)
            .ok()
            .and_then(|notice| notice["authorize"]["url"].as_str().map(str::to_owned))
        else {
            return;
        };
        let url = Url::parse(&url).unwrap();
        match &self.act {
            Act::Wait => {}
            Act::Open => follow(url),
            Act::Paste(sender) => paste_redirect(url, sender.clone()),
            Act::Hangup => hang_up(&url),
        }
    }
}

impl Write for User {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.text.extend_from_slice(buf);
        while let Some(end) = self.text[self.read..].iter().position(|b| *b == b'\n') {
            let line = String::from_utf8_lossy(&self.text[self.read..self.read + end]).into_owned();
            self.read += end + 1;
            self.see(&line);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Loads `url` without following its redirect, and pastes the redirect.
fn paste_redirect(url: Url, lines: Sender<String>) {
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap();
            let page = client.get(url).send().await.unwrap();
            let location = page.headers()[reqwest::header::LOCATION].to_str().unwrap();
            lines.send(location.to_owned()).await.unwrap();
        });
    });
}

/// Most connections a hang-up user makes.
const MAX_HANGUPS: usize = 1024;

/// Connects to the redirect URI's port and closes at once, until a connect
/// fails.
fn hang_up(url: &Url) {
    let redirect = url
        .query_pairs()
        .find(|(name, _)| name == "redirect_uri")
        .map(|(_, value)| Url::parse(&value).unwrap())
        .unwrap();
    let port = redirect.port().unwrap();
    thread::spawn(move || {
        for _ in 0..MAX_HANGUPS {
            if TcpStream::connect(("127.0.0.1", port)).is_err() {
                return;
            }
        }
    });
}
