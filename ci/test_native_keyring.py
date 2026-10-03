"""Test CI keyring lifecycle through explicit executors, never local keychains."""

from dataclasses import dataclass, field
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from typing import Mapping, Sequence
import unittest

from with_native_keyring import (
    Cancellation, Child, NativeSession, ProcessExecutor, SetupError, process_options, run,
)


@dataclass
class RecordedChild:
    pid: int
    status: int | None = None

    def poll(self) -> int | None:
        return self.status

    def wait(self, timeout: float | None = None) -> int:
        if self.status is None:
            raise subprocess.TimeoutExpired("owned fixture", timeout)
        return self.status


@dataclass
class RecordingExecutor:
    status: int = 0
    fail_at: str | None = None
    cancel: int | None = None
    calls: list[tuple[str, ...]] = field(default_factory=list)
    environments: list[dict[str, str]] = field(default_factory=list)
    password: bytes | None = None
    stopped: list[int] = field(default_factory=list)
    groups: list[tuple[str, bool]] = field(default_factory=list)

    def capture(self, args: Sequence[str], env: Mapping[str, str], timeout: float,
                *, grouped: bool = True) -> str:
        self.calls.append(tuple(args))
        self.groups.append((args[0], grouped))
        if self.fail_at and self.fail_at in args:
            raise SetupError("DO-NOT-LOG-PASSWORD")
        if list(args) == ["security", "default-keychain", "-d", "user"]:
            return '"/runner/original.keychain-db"\n'
        if list(args) == ["security", "list-keychains", "-d", "user"]:
            return '"/runner/first keychain-db"\n"/runner/original.keychain-db"\n'
        if "create-keychain" in args:
            Path(args[-1]).write_bytes(b"owned fixture")
        if "delete-keychain" in args:
            Path(args[-1]).unlink()
        if "org.freedesktop.DBus.GetNameOwner" in args:
            return "(':1.0',)\n"
        if "org.freedesktop.Secret.Service.ReadAlias" in args:
            return "(objectpath '/org/freedesktop/secrets/collection/login',)\n"
        if "org.freedesktop.DBus.Properties.Get" in args:
            return "(<false>,)\n"
        return ""

    def start(self, args: Sequence[str], env: Mapping[str, str], data: bytes | None = None,
              *, grouped: bool = True) -> RecordedChild:
        self.calls.append(tuple(args))
        self.groups.append((args[0], grouped))
        self.environments.append(dict(env))
        if args[0] == "gnome-keyring-daemon":
            self.password = data
            return RecordedChild(101)
        return RecordedChild(202, self.status)

    def wait(self, child: Child, timeout: float, cancellation: Cancellation,
             *, grouped: bool = True) -> int:
        if self.cancel is not None:
            cancellation.number = self.cancel
            return 128 + self.cancel
        return self.status

    def stop(self, child: Child, timeout: float, *, grouped: bool = True) -> None:
        self.stopped.append(child.pid)


class RecordingProcesses(ProcessExecutor):
    def __init__(self) -> None:
        self.child: Child | None = None

    def start(self, args: Sequence[str], env: Mapping[str, str], data: bytes | None = None,
              *, grouped: bool = True) -> Child:
        self.child = super().start(args, env, data, grouped=grouped)
        return self.child


def environment(root: Path, platform: str) -> dict[str, str]:
    return {
        **os.environ, "GITHUB_ACTIONS": "true", "RUNNER_OS": platform, "RUNNER_TEMP": str(root),
        "HOME": "/preserved-home", "LLVM_PROFILE_FILE": "/preserved-profile-%p.profraw",
    }


class NativeKeyringTests(unittest.TestCase):
    def test_refusal_happens_before_files_or_executor_calls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executor = RecordingExecutor()
            env = environment(root, "macOS")
            env["GITHUB_ACTIONS"] = "false"
            with self.assertRaises(SetupError):
                run(["fixture-cargo"], 900, env, executor, Cancellation())
            self.assertEqual(list(root.iterdir()), [])
            self.assertEqual(executor.calls, [])

    def test_setup_failure_never_invokes_cargo_and_restores_macos(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executor = RecordingExecutor(fail_at="unlock-keychain")
            messages: list[str] = []
            status = run(["fixture-cargo"], 900, environment(root, "macOS"), executor,
                         Cancellation(), log=messages.append)
            self.assertEqual(status, 1)
            self.assertFalse(any(call[0] == "fixture-cargo" for call in executor.calls))
            self.assert_restored(executor)
            self.assertEqual(list(root.iterdir()), [])
            self.assertNotIn("DO-NOT-LOG-PASSWORD", " ".join(messages))
            password = next(call[3] for call in executor.calls if "create-keychain" in call)
            self.assertNotIn(password, " ".join(messages))

    def test_macos_snapshot_rejects_non_posix_paths_before_state_changes(self) -> None:
        class SnapshotExecutor(RecordingExecutor):
            default_snapshot = ""
            search_snapshot = ""

            def capture(self, args: Sequence[str], env: Mapping[str, str], timeout: float,
                        *, grouped: bool = True) -> str:
                result = super().capture(args, env, timeout, grouped=grouped)
                if list(args) == ["security", "default-keychain", "-d", "user"]:
                    return self.default_snapshot
                if list(args) == ["security", "list-keychains", "-d", "user"]:
                    return self.search_snapshot
                return result

        for default, search in (
            ('"relative.keychain-db"', '"/runner/search.keychain-db"'),
            ('"/runner/default.keychain-db"', '"relative.keychain-db"'),
            ('"C:/runner/default.keychain-db"', '"C:/runner/search.keychain-db"'),
        ):
            with self.subTest(default=default, search=search), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                executor = SnapshotExecutor()
                executor.default_snapshot, executor.search_snapshot = default, search
                messages: list[str] = []
                status = run(["fixture-cargo"], 900, environment(root, "macOS"), executor,
                             Cancellation(), log=messages.append)
                self.assertEqual(status, 1)
                self.assertEqual(executor.calls, [
                    ("security", "default-keychain", "-d", "user"),
                    ("security", "list-keychains", "-d", "user"),
                ])
                self.assertEqual(list(root.iterdir()), [])
                self.assertEqual(len(messages), 1)

    def test_macos_cargo_failure_preserves_exit_and_exact_original_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executor = RecordingExecutor(status=7)
            status = run(["fixture-cargo", "--include-ignored"], 900,
                         environment(Path(directory), "macOS"), executor, Cancellation())
            self.assertEqual(status, 7)
            self.assert_restored(executor)
            self.assertEqual(executor.stopped, [202])
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_linux_uses_foreground_unlock_and_proves_unlocked_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executor = RecordingExecutor()
            status = run(["fixture-cargo"], 900, environment(Path(directory), "Linux"), executor,
                         Cancellation(), in_session=True)
            self.assertEqual(status, 0)
            daemon = executor.calls[0]
            self.assertIn("--foreground", daemon)
            self.assertIn("--unlock", daemon)
            self.assertNotIn("--start", daemon)
            self.assertIsNotNone(executor.password)
            self.assertEqual(len(executor.password or b""), 64)
            self.assertNotIn(b"\n", executor.password or b"")
            self.assertTrue(any("org.freedesktop.Secret.Service.ReadAlias" in call for call in executor.calls))
            self.assertTrue(any("org.freedesktop.DBus.GetNameOwner" in call for call in executor.calls))
            self.assertTrue(any("org.freedesktop.DBus.Properties.Get" in call for call in executor.calls))
            alias = next(call for call in executor.calls if "org.freedesktop.Secret.Service.ReadAlias" in call)
            self.assertEqual(alias[alias.index("--dest") + 1], ":1.0")
            self.assertEqual(executor.environments[-1]["HOME"], "/preserved-home")
            self.assertEqual(executor.environments[-1]["LLVM_PROFILE_FILE"], "/preserved-profile-%p.profraw")
            self.assertEqual(executor.stopped, [202, 101])
            self.assertTrue(all(not grouped for _, grouped in executor.groups))
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_linux_outer_command_owns_a_private_session_bus(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executor = RecordingExecutor(status=9)
            status = run(["fixture-cargo"], 900, environment(Path(directory), "Linux"), executor,
                         Cancellation())
            self.assertEqual(status, 9)
            self.assertEqual(executor.calls[0][:2], ("dbus-run-session", "--"))
            self.assertIn("--in-session", executor.calls[0])
            self.assertEqual(executor.stopped, [202])
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_signal_exit_runs_macos_restoration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executor = RecordingExecutor(cancel=signal.SIGTERM)
            status = run(["fixture-cargo"], 900, environment(Path(directory), "macOS"), executor,
                         Cancellation())
            self.assertEqual(status, 128 + signal.SIGTERM)
            self.assert_restored(executor)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_cleanup_failure_fails_success_but_preserves_cargo_failure(self) -> None:
        for cargo_status in (0, 7):
            with self.subTest(cargo_status=cargo_status), tempfile.TemporaryDirectory() as directory:
                executor = RecordingExecutor(status=cargo_status, fail_at="delete-keychain")
                messages: list[str] = []
                status = run(["fixture-cargo"], 900, environment(Path(directory), "macOS"), executor,
                             Cancellation(), log=messages.append)
                self.assertEqual(status, cargo_status or 1)
                self.assertEqual(len(messages), 1)
                self.assertNotIn("DO-NOT-LOG-PASSWORD", messages[0])

    def test_locked_or_missing_collection_is_not_readiness(self) -> None:
        class BadCollection(RecordingExecutor):
            def capture(self, args: Sequence[str], env: Mapping[str, str], timeout: float,
                        *, grouped: bool = True) -> str:
                if "org.freedesktop.Secret.Service.ReadAlias" in args:
                    return self.alias
                if "org.freedesktop.DBus.GetNameOwner" in args:
                    return "(':1.0',)"
                return "(<true>,)"

            alias = "(objectpath '/',)"

        with tempfile.TemporaryDirectory() as directory:
            executor = BadCollection()
            session = NativeSession(environment(Path(directory), "Linux"), executor, Cancellation())
            for alias in ("(objectpath '/',)", "(objectpath '/org/freedesktop/secrets/collection/login',)"):
                executor.alias = alias
                with self.assertRaises(SetupError):
                    session.check_collection(time.monotonic() + 2)

    def test_real_timeout_stops_owned_command_and_removes_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executor = RecordingProcesses()
            started = time.monotonic()
            status = run([sys.executable, "-c", "import time; time.sleep(60)"], 5,
                         environment(Path(directory), "Windows"), executor, Cancellation())
            self.assertLess(time.monotonic() - started, 10)
            self.assertEqual(status, 124)
            self.assertIsNotNone(executor.child)
            self.assertIsNotNone(executor.child.poll() if executor.child is not None else None)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_killed_command_is_reaped_before_group_cleanup_finishes(self) -> None:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(5)
            command = [
                sys.executable, "-c",
                "import signal,socket,sys,time; "
                "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                "ready=socket.create_connection(('127.0.0.1',int(sys.argv[1])),timeout=5); "
                "ready.sendall(b'r'); ready.close(); time.sleep(60)",
                str(listener.getsockname()[1]),
            ]
            child = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     **process_options(True))
            executor = ProcessExecutor()
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(5)
                    self.assertEqual(connection.recv(1), b"r")
                started = time.monotonic()
                status = executor.wait(child, 5, Cancellation())
                self.assertLess(time.monotonic() - started, 10)
                self.assertEqual(status, 124)
                self.assertIsNotNone(child.poll())
            finally:
                executor.stop(child, 5)

    def test_real_cancellation_stops_owned_command_and_removes_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ready = root / "ready"
            cancellation = Cancellation()
            executor = RecordingProcesses()
            worker = threading.Thread(target=self.cancel_when_ready, args=(ready, cancellation))
            worker.start()
            command = [sys.executable, "-c", "import pathlib,sys,time; pathlib.Path(sys.argv[1]).touch(); time.sleep(60)", str(ready)]
            try:
                status = run(command, 5, environment(root, "Windows"), executor, cancellation)
                self.assertEqual(status, 128 + signal.SIGTERM)
                self.assertIsNotNone(executor.child.poll() if executor.child is not None else None)
                self.assertEqual(sorted(path.name for path in root.iterdir()), ["ready"])
            finally:
                worker.join(timeout=4)
            self.assertFalse(worker.is_alive())

    def test_native_command_capture_rejects_oversized_output(self) -> None:
        with self.assertRaises(SetupError):
            ProcessExecutor().capture([sys.executable, "-c", "print('x' * 20000)"], dict(os.environ), 2)

    def test_cancelled_setup_restores_macos_before_any_cargo(self) -> None:
        cancellation = Cancellation()

        class InterruptingSetup(RecordingExecutor):
            def capture(self, args: Sequence[str], env: Mapping[str, str], timeout: float,
                        *, grouped: bool = True) -> str:
                result = super().capture(args, env, timeout, grouped=grouped)
                if "create-keychain" in args:
                    cancellation.number = signal.SIGTERM
                return result

        with tempfile.TemporaryDirectory() as directory:
            executor = InterruptingSetup()
            messages: list[str] = []
            status = run(["fixture-cargo"], 900, environment(Path(directory), "macOS"), executor,
                         cancellation, log=messages.append)
            self.assertEqual(status, 128 + signal.SIGTERM)
            self.assertFalse(any(call[0] == "fixture-cargo" for call in executor.calls))
            self.assert_restored(executor)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_failed_child_cleanup_still_restores_macos(self) -> None:
        class StopFailure(RecordingExecutor):
            def stop(self, child: Child, timeout: float, *, grouped: bool = True) -> None:
                raise SetupError("DO-NOT-LOG-PASSWORD")

        with tempfile.TemporaryDirectory() as directory:
            executor = StopFailure()
            messages: list[str] = []
            status = run(["fixture-cargo"], 900, environment(Path(directory), "macOS"), executor,
                         Cancellation(), log=messages.append)
            self.assertEqual(status, 1)
            self.assert_restored(executor)
            self.assertEqual(list(Path(directory).iterdir()), [])
            self.assertNotIn("DO-NOT-LOG-PASSWORD", " ".join(messages))

    def test_invalid_shared_root_cannot_trigger_cleanup_of_other_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            protected = root / "protected"
            protected.mkdir()
            marker = protected / "keep"
            marker.write_bytes(b"unchanged")
            executor = RecordingExecutor()
            with self.assertRaises(SetupError):
                run(["fixture-cargo"], 900, environment(root, "Linux"), executor,
                    Cancellation(), in_session=True, session_root=protected)
            self.assertEqual(marker.read_bytes(), b"unchanged")
            self.assertEqual(executor.calls, [])

    def assert_restored(self, executor: RecordingExecutor) -> None:
        self.assertIn(("security", "default-keychain", "-d", "user", "-s", "/runner/original.keychain-db"), executor.calls)
        self.assertIn(("security", "list-keychains", "-d", "user", "-s", "/runner/first keychain-db", "/runner/original.keychain-db"), executor.calls)
        self.assertEqual(executor.calls[-1][1], "delete-keychain")

    @staticmethod
    def cancel_when_ready(ready: Path, cancellation: Cancellation) -> None:
        deadline = time.monotonic() + 3
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        cancellation.number = signal.SIGTERM


if __name__ == "__main__":
    unittest.main()
