//! Access to environment variables.

/// Reads environment variables.
pub trait Env: std::fmt::Debug {
    /// Returns the variable's value, or `None` if it is unset or not valid UTF-8.
    fn var(&self, name: &str) -> Option<String>;
}

/// The process environment. Constructed only in `main.rs`.
#[derive(Debug)]
pub struct ProcessEnv;

impl Env for ProcessEnv {
    fn var(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}
