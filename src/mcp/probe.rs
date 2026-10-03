//! Finds the protocol generation a server speaks: the saved one first, then
//! the rest, newest first.

use crate::config::model::{Generation, Transport};
use crate::error::{Error, ErrorKind};
use crate::mcp::client_session::Opened;
use crate::mcp::endpoint::Endpoint;
use crate::mcp::{legacy_sse, streamable};

/// Every generation, newest first.
const ALL: [Generation; 3] = [
    Generation::Modern,
    Generation::LegacyStreamable,
    Generation::Sse,
];

/// Opens a session on the first generation that answers. Only
/// `unsupported_server` moves on to the next; any other error ends the
/// probe, so a server is never asked the same thing twice after a real
/// failure. At most three handshakes.
///
/// # Errors
/// The first error other than `unsupported_server`, or
/// `unsupported_server` when no generation answered.
pub(crate) async fn probe(
    endpoint: &Endpoint,
    transport: Transport,
    saved: Option<Generation>,
) -> Result<(Opened, Generation), Error> {
    for generation in order(transport, saved) {
        match open(endpoint, generation).await {
            Ok(opened) => return Ok((opened, generation)),
            Err(error) if error.kind() == ErrorKind::UnsupportedServer => {}
            Err(error) => return Err(error),
        }
    }
    Err(Error::new(
        ErrorKind::UnsupportedServer,
        format!(
            "{} answered none of the MCP transports mcpjump supports",
            endpoint.origin()
        ),
    ))
}

/// `-t sse` allows only SSE; otherwise the saved generation goes first.
fn order(transport: Transport, saved: Option<Generation>) -> Vec<Generation> {
    if transport == Transport::Sse {
        return vec![Generation::Sse];
    }
    let mut order: Vec<Generation> = saved.into_iter().collect();
    order.extend(
        ALL.into_iter()
            .filter(|generation| Some(*generation) != saved),
    );
    order
}

async fn open(endpoint: &Endpoint, generation: Generation) -> Result<Opened, Error> {
    match generation {
        Generation::Modern => streamable::open(endpoint, true).await,
        Generation::LegacyStreamable => streamable::open(endpoint, false).await,
        Generation::Sse => legacy_sse::open(endpoint).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_is_forced_and_the_saved_generation_goes_first() {
        use Generation::{LegacyStreamable, Modern, Sse};
        assert_eq!(order(Transport::Sse, Some(Modern)), [Sse]);
        assert_eq!(
            order(Transport::Http, None),
            [Modern, LegacyStreamable, Sse]
        );
        assert_eq!(
            order(Transport::Http, Some(Sse)),
            [Sse, Modern, LegacyStreamable]
        );
        assert_eq!(
            order(Transport::Http, Some(LegacyStreamable)),
            [LegacyStreamable, Modern, Sse]
        );
    }
}
