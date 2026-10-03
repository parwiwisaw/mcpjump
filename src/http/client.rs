//! The HTTP client for one command: rustls, a connect timeout, no automatic
//! retries, and a redirect policy chosen per request.

use std::error::Error as StdError;
use std::time::Duration;

use reqwest::redirect::{Action, Attempt, Policy};
use reqwest::{Client, Method, RequestBuilder, Response};
use tokio::time::{Instant, timeout_at};
use url::Url;

use crate::error::{Error, ErrorKind};

/// The most redirects one request follows.
pub const MAX_REDIRECTS: usize = 5;

/// How far to follow an error's sources when looking for its root cause.
const MAX_SOURCE_DEPTH: usize = 16;

/// Which redirects a request follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Redirects {
    /// Up to [`MAX_REDIRECTS`] hops, each on the request's origin: MCP and
    /// metadata requests.
    SameOrigin,
    /// None: token, registration and SSE endpoint POSTs.
    Never,
}

/// Two reqwest clients sharing one configuration, one per redirect policy.
#[derive(Debug, Clone)]
pub struct HttpClient {
    same_origin: Client,
    never: Client,
    connect_timeout: Duration,
}

impl HttpClient {
    /// Builds the clients. Retries are off, so every retry is one the caller
    /// makes on purpose.
    ///
    /// # Errors
    /// `network` if the TLS backend cannot start or `user_agent` is not a
    /// valid header value.
    pub fn new(connect_timeout: Duration, user_agent: &str) -> Result<Self, Error> {
        let same_origin = build(
            connect_timeout,
            user_agent,
            Policy::custom(same_origin_only),
        );
        let never = build(connect_timeout, user_agent, Policy::none());
        same_origin.and_then(|same_origin| {
            never.map(|never| Self {
                same_origin,
                never,
                connect_timeout,
            })
        })
    }

    /// Starts a request that follows `redirects`.
    pub fn request(&self, method: Method, url: Url, redirects: Redirects) -> RequestBuilder {
        let client = match redirects {
            Redirects::SameOrigin => &self.same_origin,
            Redirects::Never => &self.never,
        };
        client.request(method, url)
    }

    /// Sends the request and waits for the response headers until
    /// `deadline`. A redirect that was not followed is an error, never a
    /// response.
    ///
    /// # Errors
    /// `request_timeout`, `connect_timeout`, `redirect_rejected` or
    /// `network`; `invalid_header` if the request could not be built.
    pub async fn send(
        &self,
        request: RequestBuilder,
        deadline: Instant,
    ) -> Result<Response, Error> {
        let (client, request) = request.build_split();
        let request = request.map_err(|error| invalid_request(&error))?;
        let origin = request.url().origin().ascii_serialization();
        let response = timeout_at(deadline, client.execute(request))
            .await
            .map_err(|_| request_timeout(&origin))?
            .map_err(|error| self.send_error(&error, &origin))?;
        let status = response.status();
        if status.is_redirection() {
            return Err(Error::new(
                ErrorKind::RedirectRejected,
                format!("{origin} answered {status}, a redirect this request does not follow"),
            ));
        }
        Ok(response)
    }

    fn send_error(&self, error: &reqwest::Error, origin: &str) -> Error {
        if error.is_redirect() {
            Error::new(
                ErrorKind::RedirectRejected,
                format!("{origin} redirected more than {MAX_REDIRECTS} times or to another origin"),
            )
        } else if error.is_connect() && error.is_timeout() {
            Error::new(
                ErrorKind::ConnectTimeout,
                format!(
                    "could not connect to {origin} within {:?}",
                    self.connect_timeout
                ),
            )
        } else {
            network_error(error, origin)
        }
    }
}

fn build(connect_timeout: Duration, user_agent: &str, policy: Policy) -> Result<Client, Error> {
    Client::builder()
        .user_agent(user_agent)
        .connect_timeout(connect_timeout)
        .redirect(policy)
        .referer(false)
        .retry(reqwest::retry::never())
        .build()
        .map_err(|error| {
            Error::new(
                ErrorKind::Network,
                format!("could not set up the HTTP client: {}", root_cause(&error)),
            )
        })
}

/// Follows a redirect only on the original request's origin, up to
/// [`MAX_REDIRECTS`] hops. An https-to-http hop changes the origin.
fn same_origin_only(attempt: Attempt) -> Action {
    let hops = attempt.previous().len();
    let same_origin = attempt.previous().first().map(Url::origin) == Some(attempt.url().origin());
    if hops <= MAX_REDIRECTS && same_origin {
        attempt.follow()
    } else {
        attempt.error("redirect rejected")
    }
}

fn invalid_request(error: &reqwest::Error) -> Error {
    Error::new(
        ErrorKind::InvalidHeader,
        format!("could not build the request: {}", root_cause(error)),
    )
}

/// The error for a request or response that missed its deadline.
pub(crate) fn request_timeout(origin: &str) -> Error {
    Error::new(
        ErrorKind::RequestTimeout,
        format!("{origin} did not answer before the deadline"),
    )
}

/// The error for a failed connection or transfer. The message names the
/// origin and the root cause, never the full URL, which may carry secrets.
pub(crate) fn network_error(error: &reqwest::Error, origin: &str) -> Error {
    Error::new(
        ErrorKind::Network,
        format!("could not reach {origin}: {}", root_cause(error)),
    )
}

/// The innermost source's message, such as "Connection refused" or a TLS
/// certificate error, without the URL reqwest adds at the top.
fn root_cause(error: &(dyn StdError + 'static)) -> String {
    let mut cause = error;
    for _ in 0..MAX_SOURCE_DEPTH {
        match cause.source() {
            Some(source) => cause = source,
            None => break,
        }
    }
    cause.to_string()
}
