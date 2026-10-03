//! Bounded reads, atomic writes and bounded locks on real files.

use std::fs::TryLockError;
use std::io::{self, ErrorKind};
use std::thread;
use std::time::{Duration, Instant};

use mcpjump::files::{create_private_dir, lock, lock_with, read_bounded, write_atomic};

#[test]
fn reads_up_to_the_bound_and_reports_missing_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f");
    assert_eq!(read_bounded(&path, 4).unwrap(), None);
    std::fs::write(&path, "abcd").unwrap();
    assert_eq!(read_bounded(&path, 4).unwrap().as_deref(), Some("abcd"));
    let error = read_bounded(&path, 3).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::FileTooLarge);
    assert_eq!(error.to_string(), "larger than 3 bytes");
}

#[test]
fn reading_a_directory_or_invalid_utf8_fails() {
    let dir = tempfile::tempdir().unwrap();
    assert!(read_bounded(dir.path(), 4).is_err());
    let path = dir.path().join("f");
    std::fs::write(&path, [0xff, 0xfe]).unwrap();
    assert_eq!(
        read_bounded(&path, 4).unwrap_err().kind(),
        ErrorKind::InvalidData
    );
}

#[test]
fn atomic_writes_replace_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f");
    write_atomic(&path, b"one").unwrap();
    write_atomic(&path, b"two").unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "two");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn atomic_write_into_a_missing_directory_fails() {
    let dir = tempfile::tempdir().unwrap();
    let error = write_atomic(&dir.path().join("missing").join("f"), b"x").unwrap_err();
    assert_eq!(error.kind(), ErrorKind::NotFound);
}

#[test]
fn a_lock_waits_for_its_holder() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("locks").join("l");
    let held = lock(&path, Duration::ZERO).unwrap();
    let releaser = thread::spawn(move || {
        thread::sleep(Duration::from_millis(100));
        drop(held);
    });
    let start = Instant::now();
    let _second = lock(&path, Duration::from_secs(10)).unwrap();
    assert!(start.elapsed() >= Duration::from_millis(50));
    releaser.join().unwrap();
}

#[test]
fn a_lock_times_out_while_held() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("l");
    let _held = lock(&path, Duration::ZERO).unwrap();
    let error = lock(&path, Duration::ZERO).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::TimedOut);
    assert_eq!(error.to_string(), "lock still held after 0 s");
}

#[test]
fn a_lock_error_other_than_contention_returns_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let unsupported =
        |_: &std::fs::File| Err(TryLockError::Error(io::Error::from(ErrorKind::Unsupported)));
    let start = Instant::now();
    let error = lock_with(&dir.path().join("l"), Duration::from_secs(10), unsupported).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Unsupported);
    assert!(start.elapsed() < Duration::from_secs(5));
}

#[test]
fn a_lock_under_a_file_fails() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("file");
    std::fs::write(&file, "x").unwrap();
    assert!(lock(&file.join("l"), Duration::ZERO).is_err());
}

#[cfg(unix)]
#[test]
fn private_directories_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a").join("b");
    create_private_dir(&path).unwrap();
    for created in [dir.path().join("a"), path] {
        let mode = std::fs::metadata(created).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }
}

#[cfg(windows)]
#[test]
fn private_directories_are_created() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a").join("b");
    create_private_dir(&path).unwrap();
    assert!(path.is_dir());
}
