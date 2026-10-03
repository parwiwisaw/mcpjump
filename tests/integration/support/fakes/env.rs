//! An `Env` backed by a map.

use std::collections::BTreeMap;

use mcpjump::sys::env::Env;

/// Environment variables from a map; anything absent is unset.
#[derive(Debug, Default, Clone)]
pub(crate) struct MapEnv(BTreeMap<String, String>);

impl MapEnv {
    /// Adds a variable.
    pub(crate) fn with(mut self, name: &str, value: &str) -> Self {
        self.0.insert(name.to_owned(), value.to_owned());
        self
    }
}

impl Env for MapEnv {
    fn var(&self, name: &str) -> Option<String> {
        self.0.get(name).cloned()
    }
}
