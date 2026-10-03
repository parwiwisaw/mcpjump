//! Opens the user's web browser. The only file excluded from coverage: it
//! launches a real browser, which no test may do.

use std::fmt::Debug;
use std::time::Duration;

use url::Url;

use crate::sys::worker::run_within;

/// Opens URLs in a browser.
pub trait BrowserOpener: Debug + Sync {
    /// Opens `url`, waiting at most `timeout` for the launch.
    ///
    /// # Errors
    /// Why no browser opened, to show as a warning.
    fn open(&self, url: &Url, timeout: Duration) -> Result<(), String>;
}

/// The system browser. Constructed only in `main.rs`.
#[derive(Debug)]
pub struct WebBrowser;

impl BrowserOpener for WebBrowser {
    fn open(&self, url: &Url, timeout: Duration) -> Result<(), String> {
        let url = url.to_string();
        let launch = Box::new(move || webbrowser::open(&url).map_err(|error| error.to_string()));
        run_within(launch, timeout).unwrap_or_else(|| {
            Err(format!(
                "the browser did not start within browser_timeout_secs ({})",
                timeout.as_secs()
            ))
        })
    }
}
