//! HTTP for authorization: discovery, registration and token requests.
//! Every request of one phase shares that phase's deadline, and every body
//! is bounded by `max_metadata_bytes`.

use std::time::Duration;

use reqwest::header::ACCEPT;
use reqwest::{Method, RequestBuilder, StatusCode};
use serde::de::DeserializeOwned;
use tokio::time::Instant;
use url::Url;

use crate::config::limits::Limits;
use crate::error::{Error, ErrorKind};
use crate::http::body::{SizeLimit, read_body};
use crate::http::client::{HttpClient, Redirects};
use crate::mcp::connector::USER_AGENT;

/// A status and its whole body.
#[derive(Debug)]
pub(crate) struct Answer {
    pub(crate) status: StatusCode,
    pub(crate) body: Vec<u8>,
    /// The origin that answered, for messages.
    pub(crate) origin: String,
}

impl Answer {
    /// The body as JSON of type `T`.
    ///
    /// # Errors
    /// `protocol_error` naming `what` if it does not parse.
    pub(crate) fn json<T: DeserializeOwned>(&self, what: &str) -> Result<T, Error> {
        serde_json::from_slice(&self.body).map_err(|_| {
            Error::new(
                ErrorKind::ProtocolError,
                format!("{} returned invalid {what}", self.origin),
            )
        })
    }

    /// The error for a status the caller does not handle.
    pub(crate) fn unexpected(&self, what: &str) -> Error {
        Error::new(
            ErrorKind::HttpStatus,
            format!("{} answered HTTP {} for {what}", self.origin, self.status),
        )
    }
}

/// The client and deadline of one authorization phase.
#[derive(Debug)]
pub(crate) struct AuthHttp {
    client: HttpClient,
    deadline: Instant,
    budget_secs: u64,
    max_bytes: u64,
}

impl AuthHttp {
    /// Starts a phase: its requests must all finish within
    /// `auth_network_budget_secs`.
    ///
    /// # Errors
    /// `network` if the HTTP client cannot start.
    pub(crate) fn start(limits: &Limits) -> Result<Self, Error> {
        HttpClient::new(Duration::from_secs(limits.connect_timeout_secs), USER_AGENT).map(
            |client| Self {
                client,
                deadline: Instant::now() + Duration::from_secs(limits.auth_network_budget_secs),
                budget_secs: limits.auth_network_budget_secs,
                max_bytes: limits.max_metadata_bytes,
            },
        )
    }

    /// A metadata GET, following same-origin redirects.
    pub(crate) fn get(&self, url: &Url) -> RequestBuilder {
        self.client
            .request(Method::GET, url.clone(), Redirects::SameOrigin)
            .header(ACCEPT, "application/json")
    }

    /// A token or registration POST, following no redirect.
    pub(crate) fn post(&self, url: &Url) -> RequestBuilder {
        self.client
            .request(Method::POST, url.clone(), Redirects::Never)
            .header(ACCEPT, "application/json")
    }

    /// Sends `request` and reads its body within the phase's deadline.
    ///
    /// # Errors
    /// `auth_timeout` once the budget is spent; the client's and the body
    /// reader's other errors.
    pub(crate) async fn send(&self, request: RequestBuilder) -> Result<Answer, Error> {
        let response = self
            .client
            .send(request, self.deadline)
            .await
            .map_err(|error| self.budget(error))?;
        let status = response.status();
        let origin = response.url().origin().ascii_serialization();
        let body = read_body(response, SizeLimit::metadata(self.max_bytes), self.deadline)
            .await
            .map_err(|error| self.budget(error))?;
        Ok(Answer {
            status,
            body,
            origin,
        })
    }

    fn budget(&self, error: Error) -> Error {
        if error.kind() == ErrorKind::RequestTimeout {
            Error::new(
                ErrorKind::AuthTimeout,
                format!(
                    "authorization did not finish within auth_network_budget_secs ({})",
                    self.budget_secs
                ),
            )
        } else {
            error
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_body_that_is_not_the_json_asked_for_is_a_protocol_error() {
        let answer = Answer {
            status: StatusCode::OK,
            body: b"x".to_vec(),
            origin: "https://as.example".to_owned(),
        };
        let error = answer.json::<Vec<u8>>("metadata").unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ProtocolError);
        assert_eq!(
            error.message(),
            "https://as.example returned invalid metadata"
        );
    }

    #[test]
    fn only_a_timeout_spends_the_phase_budget() {
        let http = AuthHttp::start(&Limits::default()).unwrap();
        let timeout = http.budget(Error::new(ErrorKind::RequestTimeout, "slow"));
        assert_eq!(timeout.kind(), ErrorKind::AuthTimeout);
        assert_eq!(
            timeout.message(),
            "authorization did not finish within auth_network_budget_secs (60)"
        );
        let other = http.budget(Error::new(ErrorKind::Network, "down"));
        assert_eq!(other.kind(), ErrorKind::Network);
    }
}
