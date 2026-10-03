//! JSON-RPC envelope validation and bounded response correlation.

use futures::StreamExt;
use futures::stream::BoxStream;
use rmcp::model::ErrorData;
use serde_json::{Value, json};
use sse_stream::{Error as SseError, Sse};
use tokio::time::{Instant, timeout_at};

use crate::error::{Error, ErrorKind};
use crate::http::client::request_timeout;
use crate::http::sse::stream_error;
use crate::mcp::client_session::Opened;
use crate::mcp::endpoint::Endpoint;
use crate::mcp::validate::shape;

/// An event stream from the existing bounded HTTP reader.
pub(crate) type EventStream = BoxStream<'static, Result<Sse, SseError>>;

/// A correlated response can only be a result or an RPC error.
#[derive(Debug)]
pub(crate) enum Answer {
    /// The server result, retaining all fields.
    Result(Value),
    /// A correlated JSON-RPC rejection.
    Error(ErrorData),
}

/// One validated envelope relative to the outstanding request.
#[derive(Debug)]
pub(crate) enum Message {
    /// A matching server result.
    Result(Value),
    /// A matching typed rejection.
    Error(ErrorData),
    /// An independent server request requiring generation-specific handling.
    Request(Value),
    /// A notification or valid reply for another request.
    Skip,
}

impl Message {
    /// Validates the envelope before matching its id. Unrelated replies are skipped.
    pub(crate) fn read(value: &Value, id: &Value, origin: &str) -> Result<Self, Error> {
        if value["jsonrpc"] != "2.0" {
            return Err(protocol_error(
                origin,
                "sent a response that is not valid JSON-RPC",
            ));
        }
        let kinds = ["method", "result", "error"]
            .iter()
            .filter(|key| value.get(**key).is_some())
            .count();
        let received_id = value.get("id");
        if kinds != 1
            || received_id.is_some_and(|id| !id.is_string() && !id.is_u64() && !id.is_i64())
        {
            return Err(protocol_error(origin, "sent an invalid JSON-RPC envelope"));
        }
        if let Some(method) = value.get("method") {
            if !method.is_string() {
                return Err(protocol_error(origin, "sent an invalid JSON-RPC method"));
            }
            return Ok(if received_id.is_some() {
                Self::Request(value.clone())
            } else {
                Self::Skip
            });
        }
        if received_id.is_none() {
            return Err(protocol_error(origin, "sent a reply without a request id"));
        }
        let message = if let Some(error) = value.get("error") {
            Self::Error(
                serde_json::from_value(error.clone())
                    .map_err(|_| protocol_error(origin, "sent an invalid JSON-RPC error"))?,
            )
        } else {
            let result = &value["result"];
            if !result.is_object() {
                return Err(protocol_error(
                    origin,
                    "sent a result that is not an object",
                ));
            }
            Self::Result(result.clone())
        };
        Ok(if received_id == Some(id) {
            message
        } else {
            Self::Skip
        })
    }
}

/// Parses bounded JSON; depth is checked before parsing and after decoding.
pub(crate) fn parse(body: &[u8], origin: &str, max_depth: u64) -> Result<Value, Error> {
    let mut depth = 0_u64;
    let (mut quoted, mut escaped) = (false, false);
    for byte in body {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => depth += 1,
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
            if depth > max_depth {
                return Err(depth_error(origin));
            }
        }
    }
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| protocol_error(origin, "sent a response that is not valid JSON-RPC"))?;
    if value.is_array() {
        return Err(protocol_error(
            origin,
            "sent a JSON-RPC batch; batches are not supported",
        ));
    }
    if shape(&value, max_depth, u64::MAX).is_some() {
        return Err(depth_error(origin));
    }
    Ok(value)
}

/// Reads until the first matching result/error, dropping other events.
pub(crate) async fn receive(
    events: &mut EventStream,
    endpoint: &Endpoint,
    opened: &mut Opened,
    id: &Value,
    deadline: Instant,
) -> Result<Answer, Error> {
    let origin = endpoint.origin();
    loop {
        let item = timeout_at(deadline, events.next())
            .await
            .map_err(|_| request_timeout(&origin))?;
        let event = item
            .ok_or_else(|| protocol_error(&origin, "closed its SSE stream before answering"))?
            .map_err(|error| stream_error(&error, &origin))?;
        if event.event.as_deref().is_some_and(|name| name != "message") {
            continue;
        }
        let Some(data) = event.data else {
            continue;
        };
        let value = parse(data.as_bytes(), &origin, endpoint.max_json_depth)?;
        match Message::read(&value, id, &origin)? {
            Message::Skip => {}
            Message::Request(request) => {
                if opened.modern {
                    opened.unsolicited = true;
                    return Err(protocol_error(
                        &origin,
                        "sent a request, which the 2026-07-28 HTTP transport does not allow",
                    ));
                }
                opened
                    .post(endpoint, &server_reply(&request), "response", deadline)
                    .await?;
            }
            Message::Result(value) => return Ok(Answer::Result(value)),
            Message::Error(error) => return Ok(Answer::Error(error)),
        }
    }
}

/// Legacy adapters answer ping and reject other independent requests.
fn server_reply(request: &Value) -> Value {
    if request["method"] == "ping" {
        json!({"jsonrpc":"2.0","id":request["id"],"result":{}})
    } else {
        json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32601,"message":"mcpjump does not support this request"}})
    }
}

/// Reports malformed input without reflecting any payload.
pub(crate) fn protocol_error(origin: &str, what: &str) -> Error {
    Error::new(ErrorKind::ProtocolError, format!("{origin} {what}"))
}

/// Names the configured JSON depth limit without payload details.
fn depth_error(origin: &str) -> Error {
    Error::new(
        ErrorKind::ProtocolError,
        format!("the JSON response from {origin} is too deep"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unit diagnostics use a loopback origin and never make HTTP requests.
    const ORIGIN: &str = "http://127.0.0.1";

    /// Describes each envelope variant without assertion-pattern branches.
    fn label(message: &Message) -> &'static str {
        match message {
            Message::Result(_) => "result",
            Message::Error(_) => "error",
            Message::Request(_) => "request",
            Message::Skip => "skip",
        }
    }

    /// Envelope rejection covers malformed ids, methods, results and errors.
    #[test]
    fn malformed_envelopes_are_protocol_errors() {
        let cases = [
            json!({}),
            json!({"jsonrpc":"1.0","id":1,"result":{}}),
            json!({"jsonrpc":"2.0","id":true,"result":{}}),
            json!({"jsonrpc":"2.0","id":1.5,"result":{}}),
            json!({"jsonrpc":"2.0","id":null,"result":{}}),
            json!({"jsonrpc":"2.0","id":1}),
            json!({"jsonrpc":"2.0","id":1,"result":{},"error":{}}),
            json!({"jsonrpc":"2.0","method":7}),
            json!({"jsonrpc":"2.0","result":{}}),
            json!({"jsonrpc":"2.0","id":1,"error":{"code":"secret"}}),
            json!({"jsonrpc":"2.0","id":1,"result":[]}),
        ];
        for value in cases {
            let error = Message::read(&value, &json!(1), ORIGIN).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::ProtocolError);
            assert!(!error.message().contains("secret"));
        }
    }

    /// Correlation supports numeric and string ids, keeping errors as typed data.
    #[test]
    fn valid_envelopes_are_correlated_before_delivery() {
        for id in [json!(1), json!(-1), json!(u64::MAX), json!("opaque")] {
            let result = json!({"jsonrpc":"2.0","id":id,"result":{}});
            assert_eq!(
                label(&Message::read(&result, &id, ORIGIN).unwrap()),
                "result"
            );
            assert_eq!(
                label(&Message::read(&result, &json!(2), ORIGIN).unwrap()),
                "skip"
            );
            let error = json!({"jsonrpc":"2.0","id":id,"error":{"code":-32603,"message":"secret"}});
            assert_eq!(label(&Message::read(&error, &id, ORIGIN).unwrap()), "error");
            assert_eq!(
                label(&Message::read(&error, &json!(2), ORIGIN).unwrap()),
                "skip"
            );
        }
        for id in [None, Some(json!(90))] {
            let mut request = json!({"jsonrpc":"2.0","method":"ping"});
            if let Some(id) = &id {
                request["id"] = id.clone();
            }
            let message = Message::read(&request, &json!(1), ORIGIN).unwrap();
            assert_eq!(
                label(&message),
                if id.is_some() { "request" } else { "skip" }
            );
        }
    }

    /// JSON depth is enforced around strings, escapes, arrays and malformed input.
    #[test]
    fn json_depth_and_batches_are_checked_at_the_boundary() {
        let quoted = br#"{"text":"a\\\"{[}\\"}"#;
        assert!(parse(quoted, ORIGIN, 2).is_ok());
        assert!(parse(br#"{"nested":{}}"#, ORIGIN, 2).is_ok());
        for body in [br#"{"nested":{}}"#.as_slice(), br#"{"a":[{}]}"#] {
            let error = parse(body, ORIGIN, 1).unwrap_err();
            assert!(error.message().contains("too deep"));
        }
        let error = parse(br#"{"text":"secret"}"#, ORIGIN, 1).unwrap_err();
        assert!(error.message().contains("too deep"));
        assert!(parse(b"{", ORIGIN, 64).is_err());
        assert!(parse(b"}", ORIGIN, 64).is_err());
        assert!(
            parse(b"[]", ORIGIN, 64)
                .unwrap_err()
                .message()
                .contains("batches are not supported")
        );
    }
}
