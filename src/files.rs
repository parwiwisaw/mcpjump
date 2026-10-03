//! Private-file primitives: owner-only directories, bounded reads, atomic
//! writes and bounded advisory locks.

use std::fs::{DirBuilder, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use tempfile::NamedTempFile;

/// How often a lock is retried while another process holds it.
const LOCK_POLL: Duration = Duration::from_millis(25);

/// Creates `path` and missing parents. New directories are owner-only on Unix.
///
/// # Errors
/// The underlying I/O error.
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(path)
}

/// Reads a UTF-8 file of at most `max` bytes. A missing file is `Ok(None)`.
///
/// # Errors
/// `FileTooLarge` past `max` bytes, `InvalidData` for non-UTF-8 content, or the
/// underlying I/O error.
pub fn read_bounded(path: &Path, max: u64) -> io::Result<Option<String>> {
    let read = File::open(path).and_then(|file| {
        let mut text = String::new();
        file.take(max + 1).read_to_string(&mut text).map(|_| text)
    });
    match read {
        Ok(text) if text.len() as u64 > max => Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            format!("larger than {max} bytes"),
        )),
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Replaces `path` with `bytes` atomically: a temp file in the same directory
/// is written, fsynced, then renamed over the target. The temp file is
/// owner-only on Unix, so the result is too.
///
/// # Errors
/// The underlying I/O error; the original file is then left intact.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    NamedTempFile::new_in(dir)
        .and_then(|mut temp| temp.write_all(bytes).map(|()| temp))
        .and_then(|temp| temp.as_file().sync_all().map(|()| temp))
        .and_then(|temp| temp.persist(path).map_err(io::Error::from))
        .map(drop)
}

/// An exclusive advisory lock, released when dropped.
#[derive(Debug)]
pub struct FileLock {
    _file: File,
}

/// Takes an exclusive lock on `path`, creating the file and its directory,
/// retrying while another holder has it until `wait` has passed.
///
/// # Errors
/// `TimedOut` if the lock is still held after `wait`, or the I/O error from
/// creating or locking the file, such as a filesystem without locks.
pub fn lock(path: &Path, wait: Duration) -> io::Result<FileLock> {
    lock_with(path, wait, File::try_lock)
}

/// [`lock`] with the lock attempt supplied, so tests can make it fail. Only
/// contention is retried; any other failure is returned at once.
///
/// # Errors
/// As for [`lock`].
pub fn lock_with(
    path: &Path,
    wait: Duration,
    attempt: fn(&File) -> Result<(), TryLockError>,
) -> io::Result<FileLock> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let file = create_private_dir(dir).and_then(|()| {
        OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)
    })?;
    let deadline = Instant::now() + wait;
    loop {
        match attempt(&file) {
            Ok(()) => return Ok(FileLock { _file: file }),
            Err(TryLockError::Error(error)) => return Err(error),
            Err(TryLockError::WouldBlock) if Instant::now() >= deadline => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("lock still held after {} s", wait.as_secs()),
                ));
            }
            Err(TryLockError::WouldBlock) => {
                thread::sleep(LOCK_POLL.min(deadline.saturating_duration_since(Instant::now())));
            }
        }
    }
}
