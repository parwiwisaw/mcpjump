//! Seams to the operating system. Each trait has one real implementation,
//! built only in `main.rs`, and test doubles under `tests/support/fakes/`.

pub mod browser;
pub mod clock;
pub mod deadline;
pub mod env;
pub mod terminal;
pub mod worker;

/// The operating-system family, for pure functions whose result depends on
/// it. Passing it as a value lets tests cover every family on every host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// macOS, Linux and other Unix-like systems.
    Unix,
    /// Windows.
    Windows,
}

impl Platform {
    /// The platform this binary was built for.
    pub const CURRENT: Self = if cfg!(windows) {
        Self::Windows
    } else {
        Self::Unix
    };
}
