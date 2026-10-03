//! Credential records as private files: `<config_dir>/credentials/
//! <server>.<kind>.json`, the directory `0700` and each file `0600`. On
//! Unix a symlink, a directory others can open, or anything but a regular
//! file others cannot read is refused, never followed or trusted. Windows
//! relies on the per-user `%APPDATA%` ACL.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::error::{Error, ErrorKind};
use crate::files;
use crate::store::{self, CredentialStore, Key, MAX_RECORD_BYTES};

/// Permission bits for group and others; a credential file must have none.
#[cfg(unix)]
const GROUP_OTHER_BITS: u32 = 0o077;

/// Credential records in files under one directory.
#[derive(Debug)]
pub struct FileStore {
    dir: PathBuf,
}

impl FileStore {
    /// Records under `<config_dir>/credentials`.
    #[must_use]
    pub fn new(config_dir: &Path) -> Self {
        Self {
            dir: config_dir.join("credentials"),
        }
    }

    /// The file that holds `key`, once the directory is known to be safe.
    #[cfg(unix)]
    fn checked_path(&self, key: &Key) -> Result<PathBuf, Error> {
        check_dir(&self.dir).map_err(|error| io_error(&self.dir, &error))?;
        Ok(self.path(key))
    }

    /// The file that holds `key`.
    #[must_use]
    pub fn path(&self, key: &Key) -> PathBuf {
        self.dir.join(format!(
            "{}.{}.json",
            key.server().as_str(),
            key.kind().as_str()
        ))
    }
}

impl CredentialStore for FileStore {
    fn get(&self, key: &Key) -> Result<Option<Vec<u8>>, Error> {
        #[cfg(unix)]
        let path = self.checked_path(key)?;
        #[cfg(not(unix))]
        let path = self.path(key);
        let mut record = Vec::new();
        let limit = MAX_RECORD_BYTES as u64 + 1;
        let read = open_private(&path).and_then(|file| file.take(limit).read_to_end(&mut record));
        match read {
            Ok(_) if record.len() > MAX_RECORD_BYTES => Err(store::too_large(key)),
            Ok(_) => Ok(Some(record)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(io_error(&path, &error)),
        }
    }

    fn set(&self, key: &Key, record: &[u8]) -> Result<(), Error> {
        store::check_record(key, record)?;
        #[cfg(unix)]
        let path = self.checked_path(key)?;
        #[cfg(not(unix))]
        let path = self.path(key);
        files::create_private_dir(&self.dir)
            .and_then(|()| files::write_atomic(&path, record))
            .map_err(|error| io_error(&path, &error))
    }

    fn delete(&self, key: &Key) -> Result<(), Error> {
        #[cfg(unix)]
        let path = self.checked_path(key)?;
        #[cfg(not(unix))]
        let path = self.path(key);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_error(&path, &error)),
        }
    }
}

/// Refuses a credentials directory that is a symlink or that group or
/// others can access. A missing one is fine: it is created owner-only.
#[cfg(unix)]
fn check_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = match fs::symlink_metadata(dir) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        other => other?,
    };
    if !metadata.is_dir() {
        return Err(unsafe_file("is not a directory; move it aside"));
    }
    private_mode(metadata.mode(), "700")
}

/// Opens a credential file without following a symlink or blocking on a
/// FIFO, and refuses anything but a regular file group and others cannot
/// access.
#[cfg(unix)]
fn open_private(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| match error.raw_os_error() {
            Some(libc::ELOOP) => unsafe_file("is a symlink; replace it with a regular file"),
            _ => error,
        })
        .and_then(|file| file.metadata().map(|metadata| (file, metadata)))
        .and_then(|(file, metadata)| {
            if metadata.is_file() {
                private_mode(metadata.mode(), "600").map(|()| file)
            } else {
                Err(unsafe_file("is not a regular file; move it aside"))
            }
        })
}

/// Refuses `mode` if group or others have any access.
#[cfg(unix)]
fn private_mode(mode: u32, fix: &str) -> io::Result<()> {
    if mode & GROUP_OTHER_BITS == 0 {
        Ok(())
    } else {
        Err(unsafe_file(&format!(
            "is open to other users (mode {:o}); run `chmod {fix}` on it",
            mode & 0o777
        )))
    }
}

/// Opens a credential file. Windows files inherit the user-only ACL of
/// `%APPDATA%`.
#[cfg(not(unix))]
fn open_private(path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).open(path)
}

#[cfg(unix)]
fn unsafe_file(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason.to_owned())
}

fn io_error(path: &Path, error: &io::Error) -> Error {
    Error::new(
        ErrorKind::CredentialStore,
        format!("credential file {}: {error}", path.display()),
    )
}
