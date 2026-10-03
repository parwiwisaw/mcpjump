//! End-to-end checks of the built binary's version output and exit codes.

use assert_cmd::Command;

fn mcpjump() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mcpjump"))
}

#[test]
fn version_flag_exits_zero_with_version_on_stdout() {
    mcpjump()
        .arg("--version")
        .assert()
        .success()
        .stdout(format!("mcpjump {}\n", env!("CARGO_PKG_VERSION")))
        .stderr("");
}

#[test]
fn unknown_argument_exits_two() {
    mcpjump().arg("--bogus").assert().code(2).stdout("");
}
