//! Blocking work under a deadline.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Runs `work` on its own thread and waits at most `timeout` for it. On
/// timeout the thread is abandoned: it finishes on its own and its result
/// is dropped. `None` means the deadline passed.
#[must_use]
pub fn run_within<T: Send + 'static>(
    work: Box<dyn FnOnce() -> T + Send>,
    timeout: Duration,
) -> Option<T> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        // After a timeout nobody is listening; the result is not needed.
        let _unheard = sender.send(work());
    });
    receiver.recv_timeout(timeout).ok()
}
