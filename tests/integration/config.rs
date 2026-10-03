//! Locating, loading, validating and updating the config file.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::PathBuf;
use std::time::Duration;

use mcpjump::config::document::{insert_server, remove_server};
use mcpjump::config::io::{ConfigFile, MAX_CONFIG_BYTES, TEMPLATE, config_dir};
use mcpjump::config::limits::Limits;
use mcpjump::config::model::{
    Backend, Config, CredentialStoreKind, Generation, MAX_SERVERS, OutputFormat, ServerSpec,
    Transport, check_client_id, too_many_servers,
};
use mcpjump::config::validate::ServerName;
use mcpjump::error::{Error, ErrorKind};
use mcpjump::files;
use mcpjump::sys::Platform;

use crate::support::fakes::env::MapEnv;

fn dir_for(env: &MapEnv, platform: Platform) -> Result<PathBuf, String> {
    config_dir(env, platform).map_err(|error| {
        assert_eq!(error.kind(), ErrorKind::ConfigIo);
        error.message().to_owned()
    })
}

#[test]
fn mcpjump_home_wins_when_absolute() {
    let home = std::env::temp_dir();
    let env = MapEnv::default()
        .with("MCPJUMP_HOME", home.to_str().unwrap())
        .with("HOME", "/h")
        .with("APPDATA", "/a");
    for platform in [Platform::Unix, Platform::Windows] {
        assert_eq!(dir_for(&env, platform), Ok(home.clone()));
    }
    let relative = MapEnv::default().with("MCPJUMP_HOME", "rel");
    assert_eq!(
        dir_for(&relative, Platform::Unix),
        Err("MCPJUMP_HOME must be an absolute path".to_owned())
    );
}

#[test]
fn unix_uses_absolute_xdg_config_home_else_home() {
    let root = std::env::temp_dir();
    let xdg = root.join("xdg");
    let env = MapEnv::default()
        .with("MCPJUMP_HOME", "")
        .with("XDG_CONFIG_HOME", xdg.to_str().unwrap())
        .with("HOME", root.to_str().unwrap());
    assert_eq!(dir_for(&env, Platform::Unix), Ok(xdg.join("mcpjump")));
    let relative_xdg = env.clone().with("XDG_CONFIG_HOME", "rel");
    let expected = root.join(".config").join("mcpjump");
    assert_eq!(dir_for(&relative_xdg, Platform::Unix), Ok(expected.clone()));
    let empty_xdg = env.with("XDG_CONFIG_HOME", "");
    assert_eq!(dir_for(&empty_xdg, Platform::Unix), Ok(expected));
}

#[test]
fn windows_uses_absolute_appdata() {
    let appdata = std::env::temp_dir();
    let env = MapEnv::default()
        .with("APPDATA", appdata.to_str().unwrap())
        .with("HOME", "/h");
    assert_eq!(
        dir_for(&env, Platform::Windows),
        Ok(appdata.join("mcpjump"))
    );
}

#[test]
fn no_absolute_base_directory_is_an_error() {
    let message = "cannot find a config directory; set MCPJUMP_HOME".to_owned();
    let unix_only = MapEnv::default().with("APPDATA", "/a");
    assert_eq!(dir_for(&unix_only, Platform::Unix), Err(message.clone()));
    let windows_only = MapEnv::default().with("HOME", "/h");
    assert_eq!(
        dir_for(&windows_only, Platform::Windows),
        Err(message.clone())
    );
    let relative = MapEnv::default()
        .with("APPDATA", "appdata")
        .with("HOME", "home")
        .with("XDG_CONFIG_HOME", "xdg");
    for platform in [Platform::Unix, Platform::Windows] {
        assert_eq!(dir_for(&relative, platform), Err(message.clone()));
    }
}

struct Dir {
    temp: tempfile::TempDir,
    file: ConfigFile,
}

impl Dir {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let file = ConfigFile::new(temp.path().to_path_buf());
        Self { temp, file }
    }

    fn write(&self, text: &str) {
        std::fs::write(self.file.path(), text).unwrap();
    }

    fn load_error(&self, text: &str) -> (ErrorKind, String) {
        self.write(text);
        let error = self.file.load().unwrap_err();
        (error.kind(), error.message().to_owned())
    }

    fn text(&self) -> String {
        std::fs::read_to_string(self.file.path()).unwrap()
    }
}

fn invalid(message: &str) -> (ErrorKind, String) {
    (ErrorKind::ConfigInvalid, message.to_owned())
}

#[test]
fn a_missing_file_and_the_template_both_load_the_defaults() {
    let dir = Dir::new();
    assert_eq!(dir.file.path(), dir.temp.path().join("config.toml"));
    assert_eq!(dir.file.load().unwrap(), Config::default());
    dir.write(TEMPLATE);
    assert_eq!(dir.file.load().unwrap(), Config::default());
    assert_eq!(Limits::default().lock_wait(), Duration::from_secs(20));
}

const LIMIT_RANGES: [(&str, u64, u64); 18] = [
    ("connect_timeout_secs", 1, 60),
    ("request_timeout_secs", 1, 300),
    ("auth_network_budget_secs", 1, 600),
    ("tool_timeout_secs", 1, 3600),
    ("stream_idle_secs", 1, 600),
    ("login_timeout_secs", 30, 1800),
    ("validation_timeout_secs", 1, 30),
    ("stdin_timeout_secs", 1, 600),
    ("browser_timeout_secs", 1, 30),
    ("keyring_timeout_secs", 1, 60),
    ("lock_wait_secs", 2, 600),
    ("max_response_bytes", 1024, 256 << 20),
    ("max_metadata_bytes", 1024, 16 << 20),
    ("max_params_bytes", 1024, 64 << 20),
    ("max_json_depth", 8, 256),
    ("max_tool_pages", 1, 10_000),
    ("max_tools", 1, 100_000),
    ("max_tools_bytes", 1024, 256 << 20),
];

/// `[limits]` with `request_timeout_secs = 1` and `lock_wait_secs = 600`, so
/// every other limit can reach both ends of its range, plus one override.
fn limits_toml(key: &str, value: u64) -> String {
    let mut limits = BTreeMap::from([("request_timeout_secs", 1), ("lock_wait_secs", 600)]);
    limits.insert(key, value);
    let lines: Vec<String> = limits.iter().map(|(k, v)| format!("{k} = {v}")).collect();
    format!("[limits]\n{}\n", lines.join("\n"))
}

#[test]
fn every_limit_accepts_its_range_ends_and_rejects_beyond() {
    let dir = Dir::new();
    for (key, min, max) in LIMIT_RANGES {
        for value in [min, max] {
            dir.write(&limits_toml(key, value));
            assert!(dir.file.load().is_ok(), "{key} = {value}");
        }
        let range_min = if key == "lock_wait_secs" { 1 } else { min };
        for value in [range_min - 1, max + 1] {
            let message = format!("limits.{key}: {value} is outside {range_min}..={max}");
            assert_eq!(dir.load_error(&limits_toml(key, value)), invalid(&message));
        }
    }
}

#[test]
fn the_lock_wait_must_outlast_a_request() {
    let dir = Dir::new();
    let message = "limits.lock_wait_secs: must be greater than limits.request_timeout_secs";
    let text = "[limits]\nrequest_timeout_secs = 20\n";
    assert_eq!(dir.load_error(text), invalid(message));
}

#[test]
fn settings_parse_and_validate() {
    let dir = Dir::new();
    dir.write(
        "[settings]\ncredential_store = \"file\"\noutput = \"text\"\n\
         client_metadata_url = \"https://example.com/client.json\"\n",
    );
    let settings = dir.file.load().unwrap().settings;
    assert_eq!(settings.credential_store, CredentialStoreKind::File);
    assert_eq!(settings.output, OutputFormat::Text);
    assert_eq!(
        settings.client_metadata_url.unwrap().as_str(),
        "https://example.com/client.json"
    );
    let bad = "[settings]\nclient_metadata_url = \"http://example.com/c\"\n";
    let message = "settings.client_metadata_url: invalid URL: http is allowed only for loopback hosts; use https";
    assert_eq!(dir.load_error(bad), invalid(message));
}

#[test]
fn servers_parse_every_field() {
    let dir = Dir::new();
    dir.write(
        "[servers.demo]\nurl = \"https://example.com/mcp\"\ntransport = \"sse\"\n\
         generation = \"legacy_streamable\"\nheaders = { \"X-Key\" = \"${KEY}\" }\n\
         client_id = \"cid\"\ncallback_port = 8123\ncredentials = \"file\"\n\
         [servers.other]\nurl = \"https://example.com/other\"\nclient_id = \"\"\n",
    );
    let config = dir.file.load().unwrap();
    let demo = config.server(&ServerName::parse("demo").unwrap()).unwrap();
    assert_eq!(demo.spec.url().as_str(), "https://example.com/mcp");
    assert_eq!(demo.spec.transport(), Transport::Sse);
    assert_eq!(demo.generation, Some(Generation::LegacyStreamable));
    assert_eq!(demo.spec.headers()[0].raw_value(), "${KEY}");
    assert_eq!(demo.spec.client_id(), Some("cid"));
    assert_eq!(demo.spec.callback_port(), 8123);
    assert_eq!(demo.credentials, Some(Backend::File));
    let other = config.server(&ServerName::parse("other").unwrap()).unwrap();
    assert_eq!(other.spec.transport(), Transport::Http);
    assert_eq!(
        (other.spec.client_id(), other.generation, other.credentials),
        (None, None, None)
    );
    let missing = config
        .server(&ServerName::parse("nope").unwrap())
        .unwrap_err();
    assert_eq!(missing.kind(), ErrorKind::UnknownServer);
    assert_eq!(
        missing.message(),
        "no server named \"nope\"; see `mcpjump list`"
    );
}

#[test]
fn bad_server_entries_name_their_key() {
    let dir = Dir::new();
    let cases = [
        (
            "[servers.\"a b\"]\nurl = \"https://e.com\"\n",
            "servers.a b: invalid server name \"a b\": use 1 to 64 letters, digits, '_' or '-', starting with a letter or digit",
        ),
        (
            "[servers.a]\nurl = \"ftp://e.com\"\n",
            "servers.a: invalid URL: unsupported scheme \"ftp\"; use https",
        ),
        (
            "[servers.a]\nurl = \"https://e.com\"\nheaders = { Host = \"x\" }\n",
            "servers.a: invalid header \"Host\": reserved; mcpjump sets this header itself",
        ),
        (
            "[servers.a]\nurl = \"https://e.com\"\nclient_id = \"\\u0001\"\n",
            "servers.a: invalid client ID: use 1 to 512 printable ASCII characters",
        ),
    ];
    for (text, message) in cases {
        assert_eq!(dir.load_error(text), invalid(message));
    }
}

#[test]
fn syntax_and_schema_errors_give_the_line_but_not_its_text() {
    let dir = Dir::new();
    let (kind, message) = dir.load_error("[settings]\nsecret = \"hunter2\"\n");
    assert_eq!(kind, ErrorKind::ConfigInvalid);
    assert!(
        message.starts_with("config.toml (line 2): unknown field `secret`"),
        "{message}"
    );
    assert!(!message.contains("hunter2"));
    let (_, message) = dir.load_error("[limits]\nmax_tools = \"hunter2\n");
    assert!(message.starts_with("config.toml (line 2): "), "{message}");
    assert!(!message.contains("hunter2"));
    let (_, message) = dir.load_error("[servers.a]\ntransport = \"http\"\n");
    assert!(
        message.starts_with("config.toml (line 1): missing field `url`"),
        "{message}"
    );
}

#[test]
fn too_many_servers_is_too_large() {
    let dir = Dir::new();
    let servers: String = (0..=MAX_SERVERS)
        .map(|index| format!("[servers.s{index}]\nurl = \"https://e.com\"\n"))
        .collect::<Vec<_>>()
        .concat();
    assert_eq!(
        dir.load_error(&servers),
        (
            ErrorKind::ConfigTooLarge,
            "too many servers: at most 256".to_owned()
        )
    );
    assert_eq!(too_many_servers().kind(), ErrorKind::ConfigTooLarge);
}

#[test]
fn client_ids_are_bounded_printable_ascii() {
    assert_eq!(check_client_id(" ~"), Ok(()));
    assert_eq!(check_client_id(&"c".repeat(512)), Ok(()));
    for bad in ["", "é", "\u{7f}", &"c".repeat(513)] {
        assert_eq!(
            check_client_id(bad).unwrap_err().kind(),
            ErrorKind::Usage,
            "{bad:?}"
        );
    }
}

#[test]
fn unreadable_files_are_io_errors() {
    let dir = Dir::new();
    let big = "#".repeat(usize::try_from(MAX_CONFIG_BYTES).unwrap() + 1);
    let (kind, message) = dir.load_error(&big);
    assert_eq!(kind, ErrorKind::ConfigTooLarge);
    assert!(
        message.ends_with("config.toml: larger than 1048576 bytes"),
        "{message}"
    );
    std::fs::write(dir.file.path(), [0xff]).unwrap();
    assert_eq!(dir.file.load().unwrap_err().kind(), ErrorKind::ConfigIo);
    std::fs::remove_file(dir.file.path()).unwrap();
    std::fs::create_dir(dir.file.path()).unwrap();
    assert_eq!(dir.file.load().unwrap_err().kind(), ErrorKind::ConfigIo);
    let error = dir.file.update(WAIT, &|_| Ok(())).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ConfigIo);
}

fn spec() -> ServerSpec {
    ServerSpec::new(
        "https://example.com/mcp",
        Transport::Http,
        Vec::new(),
        None,
        0,
    )
    .unwrap()
}

fn name(raw: &str) -> ServerName {
    ServerName::parse(raw).unwrap()
}

const WAIT: Duration = Duration::from_secs(5);

#[test]
fn crlf_template_updates_preserve_content_with_normalized_newlines() {
    let dir = Dir::new();
    let lf_template = TEMPLATE.replace("\r\n", "\n");
    let crlf_template = lf_template.replace('\n', "\r\n");
    dir.write(&crlf_template);
    dir.file
        .update(WAIT, &|doc| insert_server(doc, &name("a"), &spec()))
        .unwrap();
    let text = dir.text();
    assert!(!text.starts_with(&crlf_template));
    assert_eq!(
        text,
        format!(
            "{lf_template}\n[servers.a]\nurl = \"https://example.com/mcp\"\ntransport = \"http\"\n"
        )
    );
}

#[test]
fn the_first_update_writes_the_template_and_keeps_comments() {
    let dir = Dir::new();
    dir.file
        .update(WAIT, &|doc| insert_server(doc, &name("a"), &spec()))
        .unwrap();
    let text = dir.text();
    let template = TEMPLATE.replace("\r\n", "\n");
    assert!(text.starts_with(&template), "{text}");
    assert!(
        text.ends_with("\n[servers.a]\nurl = \"https://example.com/mcp\"\ntransport = \"http\"\n"),
        "{text}"
    );
    dir.file
        .update(WAIT, &|doc| remove_server(doc, &name("a")))
        .unwrap();
    assert_eq!(dir.file.load().unwrap(), Config::default());
    assert!(dir.text().starts_with(&template));
}

#[test]
fn a_failed_edit_or_invalid_result_writes_nothing() {
    let dir = Dir::new();
    let original = "# mine\n[servers.a]\nurl = \"https://e.com\"\n";
    dir.write(original);
    let error = dir
        .file
        .update(WAIT, &|doc| insert_server(doc, &name("a"), &spec()))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ServerExists);
    assert_eq!(
        error.message(),
        "a server named \"a\" already exists; remove it first"
    );
    let error = dir
        .file
        .update(WAIT, &|doc| {
            doc["limits"]["max_tools"] = toml_edit::value(0);
            Ok(())
        })
        .unwrap_err();
    assert_eq!(error.message(), "limits.max_tools: 0 is outside 1..=100000");
    let error = dir
        .file
        .update(WAIT, &|doc| remove_server(doc, &name("b")))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnknownServer);
    assert_eq!(dir.text(), original);
}

#[test]
fn updates_reject_unparsable_files_and_non_table_servers() {
    let dir = Dir::new();
    dir.write("[servers\n");
    let error = dir.file.update(WAIT, &|_| Ok(())).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    assert!(
        error.message().starts_with("config.toml (line 1): "),
        "{}",
        error.message()
    );
    dir.write("servers = 1\n");
    let error = dir
        .file
        .update(WAIT, &|doc| insert_server(doc, &name("a"), &spec()))
        .unwrap_err();
    assert_eq!(
        error,
        Error::new(ErrorKind::ConfigInvalid, "servers: expected a table")
    );
    let error = dir
        .file
        .update(WAIT, &|doc| remove_server(doc, &name("a")))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnknownServer);
    dir.write("");
    let error = dir
        .file
        .update(WAIT, &|doc| remove_server(doc, &name("a")))
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::UnknownServer);
}

#[test]
fn an_update_fixing_a_broken_entry_succeeds() {
    let dir = Dir::new();
    dir.write("[servers.a]\nurl = \"ftp://e.com\"\n");
    assert!(dir.file.load().is_err());
    dir.file
        .update(WAIT, &|doc| remove_server(doc, &name("a")))
        .unwrap();
    assert_eq!(dir.file.load().unwrap(), Config::default());
}

#[test]
fn a_held_lock_times_out() {
    let dir = Dir::new();
    let lock_path = dir.temp.path().join("locks").join("config.lock");
    let _held = files::lock(&lock_path, Duration::ZERO).unwrap();
    let error = dir.file.update(Duration::ZERO, &|_| Ok(())).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ConfigLockTimeout);
    assert!(
        error
            .message()
            .ends_with("config.lock: lock still held after 0 s")
    );
}

#[test]
fn a_lock_that_cannot_be_created_is_an_io_error() {
    let dir = Dir::new();
    std::fs::write(dir.temp.path().join("locks"), "").unwrap();
    let error = dir.file.update(WAIT, &|_| Ok(())).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ConfigIo);
}

#[cfg(unix)]
#[test]
fn a_failed_write_keeps_the_original() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Dir::new();
    dir.file
        .update(WAIT, &|doc| insert_server(doc, &name("a"), &spec()))
        .unwrap();
    let before = dir.text();
    let set_mode = |mode| {
        std::fs::set_permissions(dir.temp.path(), std::fs::Permissions::from_mode(mode)).unwrap();
    };
    set_mode(0o500);
    let result = dir
        .file
        .update(WAIT, &|doc| insert_server(doc, &name("b"), &spec()));
    set_mode(0o700);
    assert_eq!(result.unwrap_err().kind(), ErrorKind::ConfigIo);
    assert_eq!(dir.text(), before);
}

#[cfg(windows)]
#[test]
fn a_failed_write_keeps_the_original() {
    let dir = Dir::new();
    dir.file
        .update(WAIT, &|doc| insert_server(doc, &name("a"), &spec()))
        .unwrap();
    let before = dir.text();
    let set_readonly = |readonly| {
        let mut permissions = std::fs::metadata(dir.file.path()).unwrap().permissions();
        permissions.set_readonly(readonly);
        std::fs::set_permissions(dir.file.path(), permissions).unwrap();
    };
    set_readonly(true);
    let result = dir
        .file
        .update(WAIT, &|doc| insert_server(doc, &name("b"), &spec()));
    set_readonly(false);
    assert_eq!(result.unwrap_err().kind(), ErrorKind::ConfigIo);
    assert_eq!(dir.text(), before);
}

#[test]
fn quoted_values_in_parser_messages_are_redacted() {
    let dir = Dir::new();
    for value in ["\"Bearer secret_SENTINEL\"", "'a\"b secret_SENTINEL'"] {
        let text = format!("[servers.a]\nurl = \"https://e.com\"\nheaders = {value}\n");
        let (kind, message) = dir.load_error(&text);
        assert_eq!(kind, ErrorKind::ConfigInvalid);
        assert_eq!(
            message,
            "config.toml (line 3): invalid type: string \"[redacted]\", expected a map"
        );
    }
}

/// Pads the config with a trailing comment so the file is `len` bytes.
fn pad_to(doc: &mut toml_edit::DocumentMut, len: usize) {
    doc.set_trailing("");
    let base = doc.to_string().len();
    doc.set_trailing(format!("#{}\n", "x".repeat(len - base - 2)));
}

#[test]
fn an_update_never_writes_a_file_too_large_to_load() {
    let dir = Dir::new();
    let limit = usize::try_from(MAX_CONFIG_BYTES).unwrap();
    let error = dir
        .file
        .update(WAIT, &|doc| {
            pad_to(doc, limit + 1);
            Ok(())
        })
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ConfigTooLarge);
    assert_eq!(
        error.message(),
        "config.toml would exceed 1048576 bytes; nothing was written"
    );
    assert!(!dir.file.path().exists());
    dir.file
        .update(WAIT, &|doc| {
            pad_to(doc, limit);
            Ok(())
        })
        .unwrap();
    assert_eq!(dir.text().len(), limit);
    assert_eq!(dir.file.load().unwrap(), Config::default());
}

#[test]
fn pre_push_red_case_colliding_insertion_fails_without_changing_config() {
    for (existing, added) in [("Demo", "demo"), ("demo", "Demo")] {
        let dir = Dir::new();
        let original = format!("[servers.{existing}]\nurl = \"https://e.com\"\n");
        dir.write(&original);
        let error = dir
            .file
            .update(WAIT, &|doc| insert_server(doc, &name(added), &spec()))
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ServerExists);
        assert_eq!(dir.text(), original);
    }
}

#[test]
fn existing_ascii_case_collisions_fail_loading_with_both_spellings() {
    for (first, second) in [("Demo", "demo"), ("demo", "Demo")] {
        let dir = Dir::new();
        let original = format!(
            "[servers.{first}]\nurl = \"https://e.com\"\n\
             [servers.{second}]\nurl = \"https://e.com\"\n"
        );
        dir.write(&original);
        assert_eq!(
            dir.file.load().unwrap_err().kind(),
            ErrorKind::ConfigInvalid
        );
        assert_eq!(dir.text(), original);
    }
}

#[test]
fn a_fresh_document_collision_rejects_before_the_update_closure() {
    use crate::store_contract::key;
    use crate::support::fakes::store::MemoryStore;
    use mcpjump::store::{CredentialStore, RecordKind};
    use std::cell::Cell;

    let dir = Dir::new();
    dir.write("[servers.Demo]\nurl = \"https://e.com\"\n");
    dir.file.load().unwrap();
    let original = "[servers.Demo]\nurl = \"https://e.com\"\n\
                    [servers.demo]\nurl = \"https://e.com\"\n";
    dir.write(original);
    let store = MemoryStore::default();
    let credential = key("Demo", RecordKind::Tokens);
    store
        .set(&credential, br#"{"sentinel":"old credentials"}"#)
        .unwrap();
    let called = Cell::new(false);
    let error = dir
        .file
        .update(WAIT, &|_| {
            called.set(true);
            store.delete(&credential)
        })
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ConfigInvalid);
    assert!(!called.get());
    assert_eq!(
        store.get(&credential).unwrap().unwrap(),
        br#"{"sentinel":"old credentials"}"#
    );
    assert_eq!(dir.text(), original);
}

#[test]
fn ascii_distinct_names_and_the_exact_server_limit_still_load() {
    let dir = Dir::new();
    let mut servers = String::new();
    for index in 0..MAX_SERVERS {
        writeln!(servers, "[servers.S{index}]\nurl = \"https://e.com\"").unwrap();
    }
    dir.write(&servers);
    assert_eq!(dir.file.load().unwrap().servers.len(), MAX_SERVERS);
    let longest = format!("A{}", "z".repeat(63));
    let other = format!("B{}", "z".repeat(63));
    dir.write(&format!(
        "[servers.{longest}]\nurl = \"https://e.com\"\n\
         [servers.{other}]\nurl = \"https://e.com\"\n"
    ));
    assert_eq!(dir.file.load().unwrap().servers.len(), 2);
}

#[test]
fn fresh_too_many_servers_reject_before_the_update_closure() {
    let dir = Dir::new();
    let mut original = String::new();
    for index in 0..=MAX_SERVERS {
        writeln!(original, "[servers.s{index}]\nurl = \"https://e.com\"").unwrap();
    }
    dir.write(&original);
    let called = std::cell::Cell::new(false);
    let error = dir
        .file
        .update(WAIT, &|_| {
            called.set(true);
            Ok(())
        })
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ConfigTooLarge);
    assert!(!called.get());
    assert_eq!(dir.text(), original);
}

#[test]
fn an_oversized_name_can_be_removed_by_a_direct_config_repair() {
    let dir = Dir::new();
    let oversized = "s".repeat(65);
    dir.write(&format!("[servers.{oversized}]\nurl = \"https://e.com\"\n"));
    assert_eq!(
        dir.file.load().unwrap_err().kind(),
        ErrorKind::ConfigInvalid
    );
    dir.file
        .update(WAIT, &|doc| {
            assert!(
                doc["servers"]
                    .as_table_mut()
                    .unwrap()
                    .remove(&oversized)
                    .is_some()
            );
            insert_server(doc, &name("valid"), &spec())
        })
        .unwrap();
    let config = dir.file.load().unwrap();
    assert_eq!(config.servers.len(), 1);
    assert!(config.servers.contains_key(&name("valid")));
}

#[test]
fn an_expired_config_update_has_no_lock_or_edit_side_effects() {
    let dir = Dir::new();
    let original = "[servers.demo]\nurl = \"https://e.com\"\n";
    dir.write(original);
    let called = std::cell::Cell::new(false);
    let expired = tokio::time::Instant::now() - Duration::from_secs(1);
    let error = dir
        .file
        .update_with_deadline(WAIT, Some(expired), &|_| {
            called.set(true);
            Ok(())
        })
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::RequestTimeout);
    assert!(!called.get());
    assert_eq!(dir.text(), original);
    assert!(!dir.file.dir().join("locks").exists());
}

#[test]
fn a_config_edit_that_consumes_its_budget_leaves_original_bytes() {
    let dir = Dir::new();
    let original = "[servers.demo]\nurl = \"https://e.com\"\n";
    dir.write(original);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let called = std::cell::Cell::new(false);
    let started = std::time::Instant::now();
    let result = dir.file.update_with_deadline(WAIT, Some(deadline), &|doc| {
        called.set(true);
        insert_server(doc, &name("new"), &spec())?;
        // The edit has started; consume its fixed budget before returning.
        // This timer tests expiration rather than ordering concurrent work.
        while tokio::time::Instant::now() < deadline {
            std::thread::park_timeout(
                deadline.saturating_duration_since(tokio::time::Instant::now()),
            );
        }
        Ok(())
    });
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(result.unwrap_err().kind(), ErrorKind::RequestTimeout);
    assert!(called.get());
    assert_eq!(dir.text(), original);
    assert_eq!(dir.file.load().unwrap().servers.len(), 1);
}
