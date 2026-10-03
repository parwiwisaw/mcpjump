//! A `SessionConnector` and `McpSession` that replay scripted answers and
//! log what the command asked for.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use mcpjump::config::model::Generation;
use mcpjump::error::Error;
use mcpjump::mcp::connector::{Connection, SessionConnector, Target};
use mcpjump::mcp::session::{BoxFuture, McpSession, Tool, ToolPage, ToolResult};
use serde_json::{Map, Value, json};

/// What the session was asked, in order: `list <cursor>`, `call <name>
/// <arguments>`, `close`.
pub(crate) type Log = Arc<Mutex<Vec<String>>>;

/// A session that answers `tools/list` pages and one `tools/call` from a
/// script.
#[derive(Debug, Default)]
pub(crate) struct FakeSession {
    pages: VecDeque<Result<ToolPage, Error>>,
    call: Option<Result<ToolResult, Error>>,
    log: Log,
}

impl FakeSession {
    /// Adds a page of tools, each with the given definition.
    pub(crate) fn page(mut self, definitions: &[Value], next_cursor: Option<&str>) -> Self {
        let tools = definitions
            .iter()
            .map(|definition| Tool {
                name: definition["name"].as_str().unwrap().to_owned(),
                definition: definition.clone(),
            })
            .collect();
        let received_count = u64::try_from(definitions.len()).unwrap_or(u64::MAX);
        let received_bytes = definitions.iter().fold(0_u64, |bytes, definition| {
            bytes.saturating_add(u64::try_from(definition.to_string().len()).unwrap_or(u64::MAX))
        });
        self.pages.push_back(Ok(ToolPage {
            tools,
            received_count,
            received_bytes,
            next_cursor: next_cursor.map(str::to_owned),
        }));
        self
    }

    /// Adds a failing `tools/list` answer.
    pub(crate) fn page_error(mut self, error: Error) -> Self {
        self.pages.push_back(Err(error));
        self
    }

    /// Sets the `tools/call` answer.
    pub(crate) fn call(mut self, result: Result<ToolResult, Error>) -> Self {
        self.call = Some(result);
        self
    }

    /// The shared log.
    pub(crate) fn log(&self) -> Log {
        Arc::clone(&self.log)
    }

    fn record(&self, entry: String) {
        self.log.lock().unwrap().push(entry);
    }
}

impl McpSession for FakeSession {
    fn list_tools_page(
        &mut self,
        cursor: Option<String>,
    ) -> BoxFuture<'_, Result<ToolPage, Error>> {
        self.record(format!("list {}", cursor.unwrap_or_default()));
        let page = self.pages.pop_front().expect("no scripted tools/list page");
        Box::pin(async move { page })
    }

    fn call_tool(
        &mut self,
        name: &str,
        arguments: Map<String, Value>,
    ) -> BoxFuture<'_, Result<ToolResult, Error>> {
        self.record(format!("call {name} {}", Value::Object(arguments)));
        let result = self.call.take().expect("no scripted tools/call answer");
        Box::pin(async move { result })
    }

    fn close(self: Box<Self>) -> BoxFuture<'static, ()> {
        self.record("close".to_owned());
        Box::pin(async {})
    }
}

/// A connector that hands out scripted connections in order and records
/// the targets it was given.
#[derive(Debug, Default)]
pub(crate) struct FakeConnector {
    answers: Mutex<VecDeque<Result<Connection, Error>>>,
    pub(crate) targets: Mutex<Vec<Target>>,
    /// A file and the text it is overwritten with during `connect`, or
    /// `None` to delete it, to change it under the running command.
    rewrite: Option<(PathBuf, Option<String>)>,
}

impl FakeConnector {
    /// Connects to `session` on `generation`.
    pub(crate) fn session(session: FakeSession, generation: Generation) -> Self {
        Self::answer(Ok(Connection {
            session: Box::new(session),
            generation,
        }))
    }

    /// Answers the first connect with `answer`.
    pub(crate) fn answer(answer: Result<Connection, Error>) -> Self {
        Self::default().then(answer)
    }

    /// Answers the next unscripted connect with `answer`.
    pub(crate) fn then(self, answer: Result<Connection, Error>) -> Self {
        self.answers.lock().unwrap().push_back(answer);
        self
    }

    /// Answers the next unscripted connect with `session` on `generation`.
    pub(crate) fn then_session(self, session: FakeSession, generation: Generation) -> Self {
        self.then(Ok(Connection {
            session: Box::new(session),
            generation,
        }))
    }

    /// Overwrites `path` with `text` when connecting.
    pub(crate) fn rewriting(mut self, path: PathBuf, text: &str) -> Self {
        self.rewrite = Some((path, Some(text.to_owned())));
        self
    }

    /// Deletes `path` when connecting.
    pub(crate) fn removing(mut self, path: PathBuf) -> Self {
        self.rewrite = Some((path, None));
        self
    }

    /// How many times `connect` ran.
    pub(crate) fn connects(&self) -> usize {
        self.targets.lock().unwrap().len()
    }
}

impl SessionConnector for FakeConnector {
    fn connect(&self, target: Target) -> BoxFuture<'_, Result<Connection, Error>> {
        self.targets.lock().unwrap().push(target);
        match &self.rewrite {
            Some((path, Some(text))) => std::fs::write(path, text).unwrap(),
            Some((path, None)) => drop(std::fs::remove_file(path)),
            None => {}
        }
        let answer = self
            .answers
            .lock()
            .unwrap()
            .pop_front()
            .expect("no scripted connection");
        Box::pin(async move { answer })
    }
}

/// A tool definition with an input schema.
pub(crate) fn tool(name: &str, input_schema: &Value) -> Value {
    json!({"name": name, "description": format!("{name} tool"), "inputSchema": input_schema})
}
