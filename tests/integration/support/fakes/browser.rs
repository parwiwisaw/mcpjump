//! `BrowserOpener` doubles: one that only records, and one that also
//! follows the URL the way a browser would, redirects included.

use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use mcpjump::sys::browser::BrowserOpener;
use url::Url;

/// What the browser does when asked to open a URL.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum Behavior {
    /// Records the URL and nothing more.
    #[default]
    Record,
    /// Fails to start with this reason.
    Fail(String),
    /// Loads the URL on a thread of its own, following redirects to the
    /// loopback callback.
    Follow,
}

/// Records every URL it is asked to open.
#[derive(Debug, Default)]
pub(crate) struct RecordingBrowser {
    pub(crate) opened: Mutex<Vec<(Url, Duration)>>,
    behavior: Mutex<Behavior>,
}

impl RecordingBrowser {
    /// Sets what later opens do.
    pub(crate) fn set(&self, behavior: Behavior) {
        *self.behavior.lock().unwrap() = behavior;
    }

    /// How many URLs it was asked to open.
    pub(crate) fn opens(&self) -> usize {
        self.opened.lock().unwrap().len()
    }
}

impl BrowserOpener for RecordingBrowser {
    fn open(&self, url: &Url, timeout: Duration) -> Result<(), String> {
        self.opened.lock().unwrap().push((url.clone(), timeout));
        match self.behavior.lock().unwrap().clone() {
            Behavior::Record => Ok(()),
            Behavior::Fail(reason) => Err(reason),
            Behavior::Follow => {
                follow(url.clone());
                Ok(())
            }
        }
    }
}

/// Loads `url` in the background, as a browser tab would.
pub(crate) fn follow(url: Url) {
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let _page = reqwest::get(url).await;
        });
    });
}
