//! Backend selection: the recorded backend wins, then the policy; `auto`
//! falls back to the file only when no keyring exists.

use std::path::Path;

use mcpjump::config::limits::Limits;
use mcpjump::config::model::{Backend, CredentialStoreKind};
use mcpjump::config::validate::ServerName;
use mcpjump::error::ErrorKind;
use mcpjump::store::RecordKind;
use mcpjump::store::select::{Request, Selected, select};

use crate::store_contract::key;
use crate::support::fakes::store::{FakeOpener, KeyringMode};

fn choose(
    opener: &FakeOpener,
    recorded: Option<Backend>,
    policy: CredentialStoreKind,
) -> Result<Selected, mcpjump::error::Error> {
    let name = ServerName::parse("demo").unwrap();
    let limits = Limits::default();
    let request = Request {
        server: &name,
        recorded,
        policy,
        config_dir: Path::new("/home/me/.config/mcpjump"),
        config_file: Path::new("/home/me/.config/mcpjump/config.toml"),
        limits: &limits,
        deadline: None,
    };
    select(opener, &request)
}

fn is_keyring(opener: &FakeOpener, selected: &Selected) -> bool {
    let tokens = key("demo", RecordKind::Tokens);
    selected.store.set(&tokens, b"{}").is_ok() && opener.keyring().accounts() == ["demo/tokens"]
}

#[test]
fn a_recorded_keyring_is_used_whatever_the_policy() {
    for policy in [
        CredentialStoreKind::Auto,
        CredentialStoreKind::Keyring,
        CredentialStoreKind::File,
    ] {
        let opener = FakeOpener::default();
        let selected = choose(&opener, Some(Backend::Keyring), policy).unwrap();
        assert_eq!(
            (selected.backend, &selected.warning),
            (Backend::Keyring, &None)
        );
        assert!(is_keyring(&opener, &selected));
    }
}

#[test]
fn a_required_keyring_that_is_missing_is_an_error_with_a_fix() {
    let cases = [
        (Some(Backend::Keyring), CredentialStoreKind::File),
        (None, CredentialStoreKind::Keyring),
    ];
    for (recorded, policy) in cases {
        let opener = FakeOpener::default();
        opener.set_mode(KeyringMode::Unavailable);
        let error = choose(&opener, recorded, policy).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::CredentialStore);
        assert!(
            error
                .message()
                .contains("not available (no keyring daemon)")
        );
        assert!(error.message().contains("credential_store = \"file\""));
    }
}

#[test]
fn a_locked_or_stalled_keyring_is_an_error_never_a_fallback() {
    for kind in [ErrorKind::CredentialStore, ErrorKind::KeyringTimeout] {
        for (recorded, policy) in [
            (None, CredentialStoreKind::Auto),
            (None, CredentialStoreKind::Keyring),
            (Some(Backend::Keyring), CredentialStoreKind::Auto),
        ] {
            let opener = FakeOpener::default();
            opener.set_mode(KeyringMode::Refuses(kind));
            assert_eq!(choose(&opener, recorded, policy).unwrap_err().kind(), kind);
        }
    }
}

#[test]
fn a_recorded_file_is_used_with_a_reminder_unless_file_is_the_policy() {
    for (policy, reminded) in [
        (CredentialStoreKind::Auto, true),
        (CredentialStoreKind::Keyring, true),
        (CredentialStoreKind::File, false),
    ] {
        let opener = FakeOpener::default();
        let selected = choose(&opener, Some(Backend::File), policy).unwrap();
        assert_eq!(selected.backend, Backend::File);
        assert_eq!(opener.opened(), 0);
        match selected.warning {
            Some(warning) => {
                assert!(reminded);
                assert!(!warning.contains('\n'));
                assert!(warning.contains("\"demo\" are stored unencrypted in"));
                assert!(warning.contains("credentials"));
            }
            None => assert!(!reminded),
        }
    }
}

#[test]
fn the_file_policy_never_opens_the_keyring_or_warns() {
    let opener = FakeOpener::default();
    let selected = choose(&opener, None, CredentialStoreKind::File).unwrap();
    assert_eq!((selected.backend, selected.warning), (Backend::File, None));
    assert_eq!(opener.opened(), 0);
}

#[test]
fn auto_prefers_the_keyring() {
    let opener = FakeOpener::default();
    let selected = choose(&opener, None, CredentialStoreKind::Auto).unwrap();
    assert_eq!(
        (selected.backend, &selected.warning),
        (Backend::Keyring, &None)
    );
    assert!(is_keyring(&opener, &selected));
}

#[test]
fn auto_without_a_keyring_falls_back_to_the_file_with_a_notice() {
    let opener = FakeOpener::default();
    opener.set_mode(KeyringMode::Unavailable);
    let selected = choose(&opener, None, CredentialStoreKind::Auto).unwrap();
    assert_eq!(selected.backend, Backend::File);
    let notice = selected.warning.unwrap();
    let credentials = Path::new("/home/me/.config/mcpjump").join("credentials");
    let unencrypted = format!("UNENCRYPTED in {}", credentials.display());
    for part in [
        "no OS keyring is available (no keyring daemon)",
        &unencrypted,
        "`mcpjump logout demo` and `mcpjump login demo`",
        "credential_store = \"file\" in /home/me/.config/mcpjump/config.toml",
    ] {
        assert!(notice.contains(part), "{part}");
    }
    assert!(notice.lines().count() > 1);
}

#[test]
fn a_selected_store_reports_its_own_failures() {
    let opener = FakeOpener::default();
    opener.set_mode(KeyringMode::Broken(ErrorKind::KeyringTimeout));
    let selected = choose(&opener, None, CredentialStoreKind::Keyring).unwrap();
    let tokens = key("demo", RecordKind::Tokens);
    for error in [
        selected.store.get(&tokens).unwrap_err(),
        selected.store.set(&tokens, b"{}").unwrap_err(),
        selected.store.delete(&tokens).unwrap_err(),
    ] {
        assert_eq!(error.kind(), ErrorKind::KeyringTimeout);
    }
}

#[test]
fn expired_selection_opens_neither_backend() {
    let opener = FakeOpener::default();
    let directory = tempfile::tempdir().unwrap();
    let name = ServerName::parse("demo").unwrap();
    let limits = Limits::default();
    let path = directory.path().join("config.toml");
    for policy in [
        CredentialStoreKind::Auto,
        CredentialStoreKind::Keyring,
        CredentialStoreKind::File,
    ] {
        let error = select(
            &opener,
            &Request {
                server: &name,
                recorded: None,
                policy,
                config_dir: directory.path(),
                config_file: &path,
                limits: &limits,
                deadline: Some(tokio::time::Instant::now() - std::time::Duration::from_secs(1)),
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::RequestTimeout);
    }
    assert_eq!(opener.opened(), 0);
    assert!(!directory.path().join("credentials").exists());
}
