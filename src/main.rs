//! Composition root: the only place real implementations are built and wired.

use std::io;

use mcpjump::Deps;
use mcpjump::mcp::connector::HttpConnector;
use mcpjump::store::system::SystemStores;
use mcpjump::sys::browser::WebBrowser;
use mcpjump::sys::clock::SystemClock;
use mcpjump::sys::env::ProcessEnv;
use mcpjump::sys::terminal::StdTerminal;

#[cfg(all(target_os = "linux", target_env = "musl"))]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[allow(
    clippy::exit,
    reason = "output is flushed; exit never waits for a keyring thread that has hung"
)]
fn main() {
    let deps = Deps {
        env: &ProcessEnv,
        connector: &HttpConnector,
        terminal: &StdTerminal,
        stores: &SystemStores,
        clock: &SystemClock,
        browser: &WebBrowser,
    };
    let code = mcpjump::run(
        std::env::args_os(),
        &deps,
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    );
    std::process::exit(i32::from(code));
}
