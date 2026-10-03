//! The error kinds and exit codes are a public contract.

use mcpjump::error::{Error, ErrorKind};

#[test]
fn kinds_and_exit_codes_are_stable() {
    let contract: Vec<(&str, u8)> = ErrorKind::ALL
        .iter()
        .map(|kind| (kind.as_str(), kind.exit_code()))
        .collect();
    assert_eq!(
        contract,
        [
            ("usage", 2),
            ("unknown_server", 2),
            ("server_exists", 2),
            ("invalid_name", 2),
            ("invalid_url", 2),
            ("invalid_header", 2),
            ("invalid_definition", 2),
            ("missing_env_var", 2),
            ("config_invalid", 5),
            ("config_too_large", 5),
            ("config_io", 5),
            ("config_lock_timeout", 5),
            ("output_io", 5),
            ("credential_store", 5),
            ("credential_invalid", 5),
            ("credential_too_large", 5),
            ("credential_lock_timeout", 5),
            ("keyring_timeout", 5),
            ("network", 4),
            ("connect_timeout", 4),
            ("request_timeout", 4),
            ("stream_timeout", 4),
            ("redirect_rejected", 4),
            ("response_too_large", 4),
            ("metadata_too_large", 4),
            ("url_rejected", 4),
            ("auth_required", 3),
            ("resource_mismatch", 3),
            ("login_timeout", 3),
            ("auth_timeout", 4),
            ("http_status", 4),
            ("invalid_params", 2),
            ("unknown_tool", 2),
            ("tool_list_limit", 4),
            ("unsupported_server", 4),
            ("session_lost", 4),
            ("delivery_unknown", 4),
            ("schema_too_complex", 4),
            ("unsupported_feature", 4),
            ("protocol_error", 4),
            ("server_error", 4),
        ]
    );
}

#[test]
fn error_carries_kind_message_and_path() {
    let error = Error::new(ErrorKind::InvalidUrl, "bad url").with_path("/url");
    assert_eq!(error.kind(), ErrorKind::InvalidUrl);
    assert_eq!(error.message(), "bad url");
    assert_eq!(error.path(), Some("/url"));
    assert_eq!(error.to_string(), "bad url");
    assert_eq!(Error::new(ErrorKind::Usage, "x").path(), None);
}

#[test]
fn config_key_relabels_as_config_invalid() {
    let error = Error::new(ErrorKind::InvalidUrl, "bad url").in_config_key("servers.a");
    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    assert_eq!(error.message(), "servers.a: bad url");
}
