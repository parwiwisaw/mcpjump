//! Exercise the real Linux launcher in isolated child processes. webbrowser
//! 1.2.4 waits for text browsers such as lynx; ordinary commands only spawn.
#![cfg(target_os = "linux")]

use std::error::Error;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use mcpjump::sys::browser::{BrowserOpener, WebBrowser};
use serde::{Deserialize, Serialize};
use url::Url;

type TestResult = Result<(), Box<dyn Error>>;
type Capture = (Receiver<io::Result<Vec<u8>>>, JoinHandle<()>);

const URL: &str = "https://example.invalid/browser-fixture?one=1&two=2";
const STREAM_LIMIT: usize = 16384;
const FILE_LIMIT: u64 = 4096;

#[derive(Debug, Serialize, Deserialize)]
struct Report {
    ok: bool,
    error: Option<String>,
    elapsed_ms: u64,
    finished_on_return: bool,
}

#[test]
fn real_linux_browser_success_passes_the_exact_url() -> TestResult {
    run_case("success")
}

#[test]
fn real_linux_browser_reports_failed_launch_without_a_fallback() -> TestResult {
    run_case("failure")
}

#[test]
fn real_linux_browser_obeys_its_launch_deadline() -> TestResult {
    run_case("timeout")
}

#[test]
fn browser_child_probe() -> TestResult {
    let Ok(mode) = std::env::var("MCPJUMP_BROWSER_PROBE") else {
        return Ok(());
    };
    if !matches!(mode.as_str(), "success" | "failure" | "timeout") {
        return Err("invalid browser probe mode".into());
    }
    let directory = std::env::current_dir()?;
    if std::env::var("BROWSER")? != "lynx"
        || std::env::var_os("PATH").as_deref() != Some(directory.as_os_str())
        || !directory.join("lynx").is_file()
    {
        return Err("browser probe requires its isolated executable directory".into());
    }
    let started = Instant::now();
    let result = WebBrowser.open(&Url::parse(URL)?, Duration::from_secs(1));
    let report = Report {
        ok: result.is_ok(),
        error: result.err(),
        elapsed_ms: u64::try_from(started.elapsed().as_millis())?,
        finished_on_return: directory.join("finished").exists(),
    };
    // The production worker may outlive its deadline. Wait for the finite
    // launcher before exiting; the parent also owns the entire process group.
    wait_for_file(
        &directory.join("finished"),
        started + Duration::from_secs(5),
    )?;
    let bytes = serde_json::to_vec(&report)?;
    if bytes.len() > usize::try_from(FILE_LIMIT)? {
        return Err("browser outcome exceeded its file limit".into());
    }
    fs::write(directory.join("outcome.json"), bytes)?;
    Ok(())
}

fn run_case(mode: &str) -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path();
    if root.as_os_str().to_string_lossy().contains(':') {
        return Err("fixture PATH must contain exactly one directory".into());
    }
    write_launcher(root, mode)?;
    let started = Instant::now();
    let work_deadline = started + Duration::from_secs(6);
    let deadline = started + Duration::from_secs(8);
    let mut child = isolated_command(root, mode)?.spawn()?;
    let stdout = capture(child.stdout.take().ok_or("stdout pipe missing")?);
    let stderr = capture(child.stderr.take().ok_or("stderr pipe missing")?);
    let status = wait_for_exit(&mut child, work_deadline);
    let cleanup = terminate_group(&mut child, deadline);
    let stdout = finish_capture(stdout, deadline);
    let stderr = finish_capture(stderr, deadline);
    cleanup?;
    let stdout = stdout?;
    let stderr = stderr?;
    assert!(status?.success(), "stdout={stdout:?}; stderr={stderr:?}");
    let report: Report = serde_json::from_slice(&read_file(&root.join("outcome.json"))?)?;
    assert_eq!(
        read_file(&root.join("arguments"))?,
        format!("1\n{URL}\n").as_bytes()
    );
    assert_eq!(read_file(&root.join("finished"))?, b"finished\n");
    match mode {
        "success" => {
            assert!(report.ok);
            assert_eq!(report.error, None);
        }
        "failure" => {
            assert!(!report.ok);
            assert_eq!(
                report.error.as_deref(),
                Some(
                    "No valid browsers detected. You can specify one in BROWSER environment variable"
                )
            );
        }
        "timeout" => {
            assert!(!report.ok);
            assert_eq!(
                report.error.as_deref(),
                Some("the browser did not start within browser_timeout_secs (1)")
            );
            assert!(report.elapsed_ms >= 900 && report.elapsed_ms < 3000);
            assert!(!report.finished_on_return);
        }
        _ => return Err("invalid fixture mode".into()),
    }
    Ok(())
}

fn write_launcher(root: &Path, mode: &str) -> TestResult {
    let ending = match mode {
        "success" | "timeout" => "exit 0\n",
        "failure" => "exit 7\n",
        _ => return Err("invalid fixture mode".into()),
    };
    let delay = if mode == "timeout" {
        "/bin/sleep 2\n"
    } else {
        ""
    };
    let script = format!(
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$#\" \"$1\" > \"$MCPJUMP_BROWSER_ARGUMENTS\"\n\
         {delay}printf 'finished\\n' > \"$MCPJUMP_BROWSER_FINISHED\"\n{ending}"
    );
    if script.len() > usize::try_from(FILE_LIMIT)? {
        return Err("browser script exceeded its file limit".into());
    }
    let executable = root.join("lynx");
    fs::write(&executable, script)?;
    fs::set_permissions(executable, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn isolated_command(root: &Path, mode: &str) -> Result<Command, Box<dyn Error>> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args([
            "--exact",
            "browser_child_probe",
            "--nocapture",
            "--test-threads=1",
        ])
        .current_dir(root)
        .env("MCPJUMP_BROWSER_PROBE", mode)
        .env("BROWSER", "lynx")
        .env("PATH", root)
        .env("MCPJUMP_BROWSER_ARGUMENTS", root.join("arguments"))
        .env("MCPJUMP_BROWSER_FINISHED", root.join("finished"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    // Inherited HOME and LLVM_PROFILE_FILE remain untouched. PATH blocks
    // every command fallback, including WSL commands detected from procfs.
    for name in [
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XDG_CURRENT_DESKTOP",
        "XDG_SESSION_DESKTOP",
        "DESKTOP_SESSION",
        "KDE_FULL_SESSION",
        "KDE_SESSION_VERSION",
        "GNOME_DESKTOP_SESSION_ID",
        "DBUS_SESSION_BUS_ADDRESS",
        "DBUS_SESSION_BUS_PID",
        "DBUS_STARTER_ADDRESS",
        "DBUS_STARTER_BUS_TYPE",
        "WSL_DISTRO_NAME",
        "WSL_INTEROP",
        "container",
        "FLATPAK_ID",
        "SWAYSOCK",
    ] {
        command.env_remove(name);
    }
    for name in [
        "XDG_DATA_HOME",
        "XDG_DATA_DIRS",
        "XDG_CONFIG_HOME",
        "XDG_CONFIG_DIRS",
        "XDG_RUNTIME_DIR",
    ] {
        let directory = root.join(name.to_ascii_lowercase());
        fs::create_dir(&directory)?;
        command.env(name, directory);
    }
    Ok(command)
}

fn capture(stream: impl Read + Send + 'static) -> Capture {
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let result = read_stream(stream);
        // A failed parent no longer needs the diagnostic bytes; EOF has
        // already closed the owned pipe before this bounded channel send.
        let _unobserved = sender.send(result);
    });
    (receiver, reader)
}

fn read_stream(mut stream: impl Read) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(STREAM_LIMIT);
    let mut block = [0; 4096];
    let mut oversized = false;
    loop {
        let count = stream.read(&mut block)?;
        if count == 0 {
            break;
        }
        let room = STREAM_LIMIT - bytes.len();
        bytes.extend_from_slice(&block[..count.min(room)]);
        oversized |= count > room;
        // Continue draining excess bytes until the owned child's deadline
        // terminates its writers; a full pipe must not stall cleanup.
    }
    if oversized {
        return Err(io::Error::other(
            "browser fixture exceeded its stream limit",
        ));
    }
    Ok(bytes)
}

fn finish_capture(
    (receiver, reader): Capture,
    deadline: Instant,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let result = receiver.recv_timeout(deadline.saturating_duration_since(Instant::now()))?;
    while !reader.is_finished() {
        if Instant::now() >= deadline {
            return Err("browser stream reader exceeded its deadline".into());
        }
        thread::sleep(Duration::from_millis(1));
    }
    reader.join().map_err(|_| "browser stream reader failed")?;
    Ok(result?)
}

fn wait_for_exit(child: &mut Child, deadline: Instant) -> io::Result<ExitStatus> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "browser child exceeded its deadline",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn terminate_group(child: &mut Child, deadline: Instant) -> TestResult {
    let mut killer = Command::new("/bin/kill")
        .args(["-KILL", "--", &format!("-{}", child.id())])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let kill_deadline = (Instant::now() + Duration::from_millis(250)).min(deadline);
    if wait_for_exit(&mut killer, kill_deadline).is_err() {
        killer.kill()?;
        wait_for_exit(&mut killer, deadline)?;
        return Err("owned browser group termination exceeded its deadline".into());
    }
    wait_for_exit(child, deadline)?;
    Ok(())
}

fn wait_for_file(path: &Path, deadline: Instant) -> TestResult {
    while !path.exists() {
        if Instant::now() >= deadline {
            return Err("finite browser launcher did not complete".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

fn read_file(path: &Path) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(FILE_LIMIT + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > usize::try_from(FILE_LIMIT).map_err(io::Error::other)? {
        return Err(io::Error::other("browser fixture exceeded its file limit"));
    }
    Ok(bytes)
}
