//! One server's OAuth records in its credential backend. A save takes the
//! config lock, then the server lock, and records the backend it used, so
//! a server's records never end up split across two backends.

use std::cell::RefCell;

use crate::commands::Context;
use crate::config::document;
use crate::config::model::Backend;
use crate::config::validate::ServerName;
use crate::error::Error;
use crate::store::record::{self, Record};
use crate::store::select::{self, Request, Selected, StoreOpener};
use crate::store::{Key, RecordKind, lock};

/// The records of one server.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Vault<'a> {
    pub(crate) name: &'a ServerName,
    pub(crate) context: &'a Context,
    pub(crate) stores: &'a dyn StoreOpener,
}

impl Vault<'_> {
    /// The store for the recorded `backend`.
    ///
    /// # Errors
    /// The selection errors, e.g. a keyring that is now unavailable.
    pub(crate) fn open(&self, backend: Backend) -> Result<Selected, Error> {
        self.select(Some(backend))
    }

    /// The stored `kind` record in the `recorded` backend; `None` when no
    /// backend is recorded or it holds no such record.
    ///
    /// # Errors
    /// The selection and store errors; `credential_invalid` for a corrupt
    /// record.
    pub(crate) fn load<R: Record>(
        &self,
        recorded: Option<Backend>,
        kind: RecordKind,
    ) -> Result<Option<R>, Error> {
        let Some(backend) = recorded else {
            return Ok(None);
        };
        self.open(backend)
            .and_then(|selected| self.read(&*selected.store, kind))
    }

    /// Reads `kind` from `store`.
    ///
    /// # Errors
    /// The store's errors; `credential_invalid` for a corrupt record.
    pub(crate) fn read<R: Record>(
        &self,
        store: &dyn crate::store::CredentialStore,
        kind: RecordKind,
    ) -> Result<Option<R>, Error> {
        let key = self.key(kind);
        store
            .get(&key)?
            .map(|bytes| record::decode(&key, &bytes))
            .transpose()
    }

    /// Stores `record` as `kind` and records the backend. Returns the
    /// backend and a notice for stderr when it is the file.
    ///
    /// # Errors
    /// The config, lock, selection and store errors.
    pub(crate) fn save<R: Record>(
        &self,
        kind: RecordKind,
        record: &R,
    ) -> Result<(Backend, Option<String>), Error> {
        let bytes = record::encode(record);
        let saved = RefCell::new(None);
        let limits = &self.context.config.limits;
        self.context.file.update(limits.lock_wait(), &|doc| {
            let selected =
                document::credentials(doc, self.name).and_then(|recorded| self.select(recorded))?;
            lock::with_server_lock(
                self.context.file.dir(),
                self.name,
                limits.lock_wait(),
                &|| selected.store.set(&self.key(kind), &bytes),
            )
            .and_then(|()| document::set_credentials(doc, self.name, selected.backend))?;
            saved.replace(Some((selected.backend, selected.warning)));
            Ok(())
        })?;
        Ok(saved.into_inner().unwrap_or((Backend::File, None)))
    }

    /// Deletes the tokens and keeps the registration. Returns whether a
    /// backend was recorded.
    ///
    /// # Errors
    /// The config, lock, selection and store errors.
    pub(crate) fn forget_tokens(&self) -> Result<bool, Error> {
        let found = RefCell::new(false);
        let limits = &self.context.config.limits;
        self.context.file.update(limits.lock_wait(), &|doc| {
            let Some(backend) = document::credentials(doc, self.name)? else {
                return Ok(());
            };
            let selected = self.open(backend)?;
            lock::with_server_lock(
                self.context.file.dir(),
                self.name,
                limits.lock_wait(),
                &|| selected.store.delete(&self.key(RecordKind::Tokens)),
            )?;
            found.replace(true);
            Ok(())
        })?;
        Ok(found.into_inner())
    }

    pub(crate) fn key(&self, kind: RecordKind) -> Key {
        Key::new(self.name.clone(), kind)
    }

    fn select(&self, recorded: Option<Backend>) -> Result<Selected, Error> {
        let config_file = self.context.file.path();
        select::select(
            self.stores,
            &Request {
                server: self.name,
                recorded,
                policy: self.context.config.settings.credential_store,
                config_dir: self.context.file.dir(),
                config_file: &config_file,
                limits: &self.context.config.limits,
            },
        )
    }
}
