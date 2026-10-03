//! Ordered, byte-preserving HTTP and HTTP+SSE replies, without rmcp models.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use futures::stream;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use url::Url;

/// Maximum exchanges, queued frames and bytes per fixture request or reply.
const MAX_STEPS: usize = 64;
/// Maximum body size, including one byte beyond the MCP error-body cap.
const MAX_BYTES: usize = 64 * 1024 + 1;
/// Maximum queued frames on the legacy GET stream.
const MAX_FRAMES: usize = 16;

/// One request observed at the wire boundary.
#[derive(Clone, Debug)]
pub(crate) struct Received {
    /// HTTP verb.
    pub(crate) verb: Method,
    /// Path and query as received.
    pub(crate) path: String,
    /// Protocol and configured test headers only.
    pub(crate) headers: HeaderMap,
    /// JSON body, or null for GET and DELETE.
    pub(crate) body: Value,
}

impl Received {
    /// RPC method, response, GET or DELETE, for ordered script assertions.
    pub(crate) fn label(&self) -> &str {
        if self.verb == Method::POST {
            self.body["method"].as_str().unwrap_or("response")
        } else {
            self.verb.as_str()
        }
    }
}

/// Where literal response bytes go.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Delivery {
    /// A finite HTTP response body.
    Body,
    /// An HTTP reply stream kept open until dropped or the fixture deadline.
    Open,
    /// The legacy GET stream, retained for later POST replies.
    Start,
    /// Push onto the GET stream; optionally end it immediately afterwards.
    Push(bool),
    /// Break the HTTP body before a complete reply (a network failure).
    Broken,
}

/// One expected request and its literal reply.
#[derive(Debug)]
pub(crate) struct Step {
    /// Expected RPC method or HTTP verb.
    pub(crate) method: &'static str,
    /// Response status.
    pub(crate) status: StatusCode,
    /// Response content type.
    pub(crate) content_type: &'static str,
    /// Bytes returned verbatim; never parsed or serialized by the fixture.
    pub(crate) body: String,
    /// Extra response headers.
    pub(crate) headers: HeaderMap,
    /// Reply location and lifetime.
    pub(crate) delivery: Delivery,
}

impl Step {
    /// A finite reply with a chosen status, media type and literal bytes.
    pub(crate) fn new(
        method: &'static str,
        status: u16,
        media: &'static str,
        body: String,
    ) -> Self {
        assert!(body.len() <= MAX_BYTES);
        Self {
            method,
            status: StatusCode::from_u16(status).unwrap(),
            content_type: media,
            body,
            headers: HeaderMap::new(),
            delivery: Delivery::Body,
        }
    }

    /// Attach the session header the test selected.
    pub(crate) fn session(mut self, value: &'static str) -> Self {
        self.headers
            .insert("mcp-session-id", value.parse().unwrap());
        self
    }

    /// Choose how the reply is delivered.
    pub(crate) fn deliver(mut self, delivery: Delivery) -> Self {
        self.delivery = delivery;
        self
    }
}

/// Shared script, request log and GET stream ownership.
#[derive(Debug)]
struct Script {
    /// Remaining exchanges, bounded by `MAX_STEPS`.
    steps: VecDeque<Step>,
    /// Expected and actual labels, including unexpected requests.
    expected: Vec<&'static str>,
    /// Recorded exchanges, bounded by `MAX_STEPS`.
    received: Vec<Received>,
    /// Sender that owns the legacy GET stream.
    sender: Option<mpsc::Sender<String>>,
}

/// A server and its inspectable script. Dropping it aborts the listener.
#[derive(Debug)]
pub(crate) struct Fixture {
    /// Configured endpoint, shared by POST, GET and DELETE.
    pub(crate) url: Url,
    /// Script and recorded requests.
    script: Arc<Mutex<Script>>,
    /// Number of response streams whose bodies are still owned by HTTP.
    active: Arc<AtomicUsize>,
    /// Listener lifetime.
    task: JoinHandle<()>,
}

impl Fixture {
    /// Binds only loopback and serves the bounded script on any path.
    pub(crate) async fn new(steps: Vec<Step>) -> Self {
        assert!(steps.len() <= MAX_STEPS);
        let script = Arc::new(Mutex::new(Script {
            expected: steps.iter().map(|step| step.method).collect(),
            steps: steps.into(),
            received: Vec::new(),
            sender: None,
        }));
        let active = Arc::new(AtomicUsize::new(0));
        let router = Router::new()
            .fallback(on_request)
            .layer(DefaultBodyLimit::max(MAX_BYTES))
            .with_state((Arc::clone(&script), Arc::clone(&active)));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}/mcp", listener.local_addr().unwrap())).unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self {
            url,
            script,
            active,
            task,
        }
    }

    /// A snapshot of all requests received so far.
    pub(crate) fn received(&self) -> Vec<Received> {
        self.script.lock().unwrap().received.clone()
    }

    /// Checks that each scripted exchange happened, in order, exactly once.
    pub(crate) fn finished(&self) {
        let script = self.script.lock().unwrap();
        assert!(
            script.steps.is_empty(),
            "unconsumed steps: {:?}",
            script.steps
        );
        let labels: Vec<_> = script.received.iter().map(Received::label).collect();
        assert_eq!(labels, script.expected);
    }

    /// Waits briefly for HTTP to drop all response bodies after session close.
    pub(crate) async fn cleaned_up(&self) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while self.active.load(Ordering::SeqCst) != 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }
}

impl Drop for Fixture {
    /// Close the GET sender and stop accepting connections.
    fn drop(&mut self) {
        self.script.lock().unwrap().sender = None;
        self.task.abort();
    }
}

/// Records the request before consuming the next scripted response.
async fn on_request(
    State((script, active)): State<(Arc<Mutex<Script>>, Arc<AtomicUsize>)>,
    verb: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let received = Received {
        verb,
        path: uri.path_and_query().unwrap().to_string(),
        headers: selected(&headers),
        body: if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body).unwrap()
        },
    };
    let mut script = script.lock().unwrap();
    assert!(script.received.len() < MAX_STEPS);
    script.received.push(received);
    let Some(step) = script.steps.pop_front() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let body = reply_body(&mut script, &active, step.body, step.delivery);
    let mut response = (step.status, [("content-type", step.content_type)], body).into_response();
    response.headers_mut().extend(step.headers);
    response
}

/// Retains only headers that wire tests assert, including dummy credentials.
fn selected(headers: &HeaderMap) -> HeaderMap {
    headers
        .iter()
        .filter(|(name, _)| {
            name.as_str().starts_with("mcp-")
                || ["authorization", "x-key", "accept", "content-type"].contains(&name.as_str())
        })
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

/// Delivers bytes locally, on the GET stream, or as a broken transfer.
fn reply_body(
    script: &mut Script,
    active: &Arc<AtomicUsize>,
    body: String,
    delivery: Delivery,
) -> Body {
    match delivery {
        Delivery::Body => Body::from(body),
        Delivery::Open | Delivery::Start => {
            let (sender, receiver) = mpsc::channel(MAX_FRAMES);
            sender.try_send(body).unwrap();
            let keep = if matches!(delivery, Delivery::Start) {
                script.sender = Some(sender);
                None
            } else {
                Some(sender)
            };
            held_body(receiver, keep, Arc::clone(active))
        }
        Delivery::Push(end) => {
            if !body.is_empty() {
                script.sender.as_ref().unwrap().try_send(body).unwrap();
            }
            if end {
                script.sender = None;
            }
            Body::empty()
        }
        Delivery::Broken => Body::from_stream(stream::iter([
            Ok(Bytes::from(body)),
            Err(std::io::Error::other("scripted disconnect")),
        ])),
    }
}

/// Counts stream ownership, including bodies dropped by the client.
#[derive(Debug)]
struct Held {
    /// Frames, bounded by `MAX_FRAMES`.
    receiver: mpsc::Receiver<String>,
    /// Keeps a standalone reply open.
    _sender: Option<mpsc::Sender<String>>,
    /// Shared ownership count.
    active: Arc<AtomicUsize>,
    /// Absolute lifetime bound, even if no client drops the stream.
    deadline: tokio::time::Instant,
}

impl Drop for Held {
    /// Record cancellation or EOF at the HTTP body boundary.
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

/// An open stream with a five second safety deadline and explicit ownership.
fn held_body(
    receiver: mpsc::Receiver<String>,
    sender: Option<mpsc::Sender<String>>,
    active: Arc<AtomicUsize>,
) -> Body {
    active.fetch_add(1, Ordering::SeqCst);
    let held = Held {
        receiver,
        _sender: sender,
        active,
        deadline: tokio::time::Instant::now() + Duration::from_secs(5),
    };
    Body::from_stream(stream::unfold(held, |mut held| async move {
        let frame = tokio::time::timeout_at(held.deadline, held.receiver.recv())
            .await
            .ok()??;
        Some((Ok::<_, std::io::Error>(Bytes::from(frame)), held))
    }))
}
