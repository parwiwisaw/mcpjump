"""Compare profiler flushing and detached-thread exit with the active compiler."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile

from with_native_keyring import ProcessExecutor


SOURCE = """use std::{process::ExitCode, sync::mpsc, thread, time::Duration};

fn main() -> ExitCode {
    let (sender, receiver) = mpsc::sync_channel(1);
    let _detached = thread::spawn(move || {
        sender.send(()).unwrap();
        thread::sleep(Duration::from_secs(60));
    });
    receiver.recv_timeout(Duration::from_secs(2)).unwrap();
    println!("worker ready");
    if std::env::args().nth(1).as_deref() == Some("exit") {
        std::process::exit(0);
    }
    ExitCode::SUCCESS
}
"""


def main() -> None:
    executor = ProcessExecutor()
    env = dict(os.environ)
    compiler = executor.capture(["rustc", "--version"], env, 10).strip()
    with tempfile.TemporaryDirectory(prefix="mcpjump-profile-exit-", dir=env.get("RUNNER_TEMP")) as directory:
        root = Path(directory)
        source = root / "profile_exit.rs"
        source.write_text(SOURCE, encoding="utf-8")
        binary = root / ("profile_exit.exe" if os.name == "nt" else "profile_exit")
        executor.capture([
            "rustc", "--edition=2024", "-Dwarnings", "-Cinstrument-coverage",
            "-Copt-level=0", "-Ccodegen-units=1", "--crate-name", "profile_exit",
            str(source), "-o", str(binary),
        ], env, 60)
        sizes: dict[str, int] = {}
        for mode in ("exit", "return"):
            profile = root / f"{mode}.profraw"
            child_env = {**env, "LLVM_PROFILE_FILE": str(profile)}
            output = executor.capture([str(binary), mode], child_env, 5)
            if output != "worker ready\n":
                raise AssertionError(f"{mode}: child output differed")
            size = profile.stat().st_size if profile.exists() else 0
            if not 0 <= size <= 1024 * 1024:
                raise AssertionError(f"{mode}: child profile exceeded its bound")
            sizes[mode] = size
        if sizes["return"] == 0:
            raise AssertionError("normal return did not flush its profile")
        print(json.dumps({"compiler": compiler, "host": os.name, "profile_bytes": sizes,
                          "detached_worker_did_not_delay_exit": True}))


if __name__ == "__main__":
    main()
