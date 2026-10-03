"""Run CI contracts with an owned, disposable native credential store."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import math
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from types import FrameType
from typing import BinaryIO, Callable, Mapping, Protocol, Sequence


class SetupError(Exception):
    """A failed prerequisite; diagnostics deliberately omit command arguments."""


@dataclass
class Cancellation:
    number: int | None = None


class Child(Protocol):
    pid: int

    def poll(self) -> int | None: ...
    def wait(self, timeout: float | None = None) -> int: ...


class Executor(Protocol):
    def capture(self, args: Sequence[str], env: Mapping[str, str], timeout: float,
                *, grouped: bool = True) -> str: ...
    def start(self, args: Sequence[str], env: Mapping[str, str], data: bytes | None = None,
              *, grouped: bool = True) -> Child: ...
    def wait(self, child: Child, timeout: float, cancellation: Cancellation,
             *, grouped: bool = True) -> int: ...
    def stop(self, child: Child, timeout: float, *, grouped: bool = True) -> None: ...


def remaining(deadline: float, cap: float) -> float:
    seconds = min(cap, deadline - time.monotonic())
    if seconds <= 0:
        raise SetupError("deadline exhausted")
    return seconds


def drain(stream: BinaryIO, output: bytearray, oversized: threading.Event) -> None:
    with stream:
        while block := stream.read(4096):
            room = 16384 - len(output)
            output.extend(block[:room])
            if len(block) > room:
                oversized.set()


def signal_group(pid: int, number: int) -> bool:
    try:
        os.killpg(pid, number)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # A group that cannot be probed/signalled is still owned. Keep
        # polling/reaping, and fail at the deadline unless it disappears.
        return True


def drain_group(child: Child, deadline: float) -> None:
    signal_group(child.pid, signal.SIGTERM)
    grace = time.monotonic() + max(0, deadline - time.monotonic()) / 2
    while time.monotonic() < grace:
        child.poll()  # Reap the leader, but continue owning its remaining group.
        if not signal_group(child.pid, 0):
            return
        time.sleep(min(0.05, max(0, grace - time.monotonic())))
    signal_group(child.pid, signal.SIGKILL)
    while time.monotonic() < deadline:
        child.poll()
        if not signal_group(child.pid, 0):
            return
        time.sleep(min(0.05, max(0, deadline - time.monotonic())))
    child.poll()  # Reap a leader killed during the last bounded wait.
    if signal_group(child.pid, 0):
        raise SetupError("owned process group did not exit")


class ProcessExecutor:
    def start(self, args: Sequence[str], env: Mapping[str, str], data: bytes | None = None,
              *, grouped: bool = True) -> Child:
        options = process_options(grouped)
        child = subprocess.Popen(
            list(args), env=dict(env), stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
            stdout=subprocess.DEVNULL if data is not None else None,
            stderr=subprocess.DEVNULL if data is not None else None,
            **options,
        )
        if data is not None:
            try:
                assert child.stdin is not None
                with child.stdin:
                    child.stdin.write(data)
            except OSError:
                self.stop(child, 20, grouped=grouped)
                raise SetupError("password delivery failed") from None
        return child

    def wait(self, child: Child, timeout: float, cancellation: Cancellation,
             *, grouped: bool = True) -> int:
        grace = min(10, timeout / 4)
        deadline = time.monotonic() + timeout - grace
        while time.monotonic() < deadline and cancellation.number is None:
            try:
                status = child.wait(timeout=max(0.001, min(0.2, deadline - time.monotonic())))
                return status if status >= 0 else 128 - status
            except subprocess.TimeoutExpired:
                continue
        self.stop(child, grace, grouped=grouped)
        return 128 + cancellation.number if cancellation.number is not None else 124

    def stop(self, child: Child, timeout: float, *, grouped: bool = True) -> None:
        deadline = time.monotonic() + timeout
        if os.name == "nt":
            if child.poll() is None:
                result = subprocess.run(
                    ["taskkill", "/PID", str(child.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    check=False, timeout=remaining(deadline, 10),
                )
                if result.returncode != 0 and child.poll() is None:
                    raise SetupError("owned process termination failed")
        elif not grouped:
            try:
                os.kill(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                child.wait(timeout=remaining(deadline, timeout))
                return
            try:
                child.wait(timeout=remaining(deadline, min(5, timeout / 2)))
            except subprocess.TimeoutExpired:
                os.kill(child.pid, signal.SIGKILL)
        else:
            drain_group(child, deadline)
        if child.poll() is None:
            child.wait(timeout=remaining(deadline, timeout))

    def capture(self, args: Sequence[str], env: Mapping[str, str], timeout: float,
                *, grouped: bool = True) -> str:
        deadline = time.monotonic() + timeout
        output = bytearray()
        oversized = threading.Event()
        options = process_options(grouped)
        child = subprocess.Popen(
            list(args), env=dict(env), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, **options,
        )
        assert child.stdout is not None
        reader = threading.Thread(target=drain, args=(child.stdout, output, oversized))
        reader.start()
        try:
            status = self.wait(child, remaining(deadline, timeout) * 0.9, Cancellation(), grouped=grouped)
        finally:
            self.stop(child, max(0.001, deadline - time.monotonic()), grouped=grouped)
            reader.join(timeout=max(0.001, deadline - time.monotonic()))
        if reader.is_alive() or oversized.is_set() or status != 0:
            raise SetupError("native command failed")
        try:
            return output.decode("utf-8")
        except UnicodeError:
            raise SetupError("native command output was invalid") from None


@dataclass
class NativeSession:
    env: dict[str, str]
    executor: Executor
    cancellation: Cancellation
    root: Path | None = None
    daemon: Child | None = None
    keychain: Path | None = None
    original_default: str | None = None
    original_search: list[str] | None = None
    cleaning: bool = False

    def command(self, args: Sequence[str], deadline: float, cap: float = 10) -> str:
        if self.cancellation.number is not None and not self.cleaning:
            raise SetupError("native setup cancelled")
        return self.executor.capture(args, self.env, remaining(deadline, cap),
                                     grouped=self.env["RUNNER_OS"] != "Linux")

    def prepare(self, cancellation: Cancellation) -> None:
        deadline = time.monotonic() + 60
        if self.root is None:
            self.root = Path(tempfile.mkdtemp(prefix="mcpjump-keyring-", dir=self.env["RUNNER_TEMP"]))
        self.root.chmod(0o700)
        if self.env["RUNNER_OS"] == "Linux":
            self.prepare_linux(deadline, cancellation)
        elif self.env["RUNNER_OS"] == "macOS":
            self.prepare_macos(deadline)

    def prepare_linux(self, deadline: float, cancellation: Cancellation) -> None:
        assert self.root is not None
        for name in ("XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR"):
            directory = self.root / name.lower()
            directory.mkdir(mode=0o700)
            self.env[name] = str(directory)
        self.env.pop("GNOME_KEYRING_CONTROL", None)
        password = secrets.token_hex(32).encode("ascii")
        self.daemon = self.executor.start([
            "gnome-keyring-daemon", "--foreground", "--unlock", "--components=secrets",
            "--control-directory=" + self.env["XDG_RUNTIME_DIR"],
        ], self.env, password, grouped=False)
        ready_until = time.monotonic() + remaining(deadline, 15)
        for attempt in range(20):
            if cancellation.number is not None or self.daemon.poll() is not None:
                raise SetupError("native keyring startup interrupted")
            try:
                self.check_collection(ready_until)
                return
            except SetupError:
                if attempt == 19 or time.monotonic() >= ready_until:
                    raise SetupError("native keyring did not become ready") from None
                time.sleep(min(0.25, remaining(ready_until, 0.25)))
        raise SetupError("native keyring did not become ready")

    def check_collection(self, deadline: float) -> None:
        # ReadAlias on an unclaimed well-known name autoactivates another
        # daemon. Resolve the foreground daemon's unique owner without
        # activation, then keep readiness calls addressed to that owner.
        owner = self.command([
            "gdbus", "call", "--session", "--dest", "org.freedesktop.DBus",
            "--object-path", "/org/freedesktop/DBus", "--method",
            "org.freedesktop.DBus.GetNameOwner", "org.freedesktop.secrets",
        ], deadline, 2).strip()
        unique = re.fullmatch(r"\('(:[0-9]+\.[0-9]+)',\)", owner)
        if unique is None:
            raise SetupError("native daemon has not claimed its service")
        prefix = ["gdbus", "call", "--session", "--dest", unique.group(1)]
        alias = self.command(prefix + [
            "--object-path", "/org/freedesktop/secrets",
            "--method", "org.freedesktop.Secret.Service.ReadAlias", "default",
        ], deadline, 2).strip()
        match = re.fullmatch(r"\(objectpath '(/org/freedesktop/secrets/collection/[A-Za-z0-9_]+)',\)", alias)
        if match is None:
            raise SetupError("default collection missing")
        locked = self.command(prefix + [
            "--object-path", match.group(1), "--method", "org.freedesktop.DBus.Properties.Get",
            "org.freedesktop.Secret.Collection", "Locked",
        ], deadline, 2).strip()
        if locked != "(<false>,)":
            raise SetupError("default collection locked")

    def prepare_macos(self, deadline: float) -> None:
        assert self.root is not None
        default = shlex.split(self.command(["security", "default-keychain", "-d", "user"], deadline))
        search = shlex.split(self.command(["security", "list-keychains", "-d", "user"], deadline))
        if len(default) != 1 or len(search) > 64 or any(not PurePosixPath(path).is_absolute() for path in default + search):
            raise SetupError("keychain snapshot invalid")
        self.original_default, self.original_search = default[0], search
        self.keychain = self.root / "ci.keychain-db"
        password = secrets.token_hex(32)
        self.command(["security", "create-keychain", "-p", password, str(self.keychain)], deadline)
        self.command(["security", "unlock-keychain", "-p", password, str(self.keychain)], deadline)
        self.command(["security", "set-keychain-settings", "-lut", "7200", str(self.keychain)], deadline)
        self.command(["security", "default-keychain", "-d", "user", "-s", str(self.keychain)], deadline)
        self.command(["security", "list-keychains", "-d", "user", "-s", str(self.keychain)], deadline)

    def cleanup(self) -> None:
        self.cleaning = True
        deadline = time.monotonic() + (30 if self.env["RUNNER_OS"] == "macOS" else 20)
        failed = False
        if self.daemon is not None:
            try:
                self.executor.stop(self.daemon, remaining(deadline, 20), grouped=False)
            except (OSError, SetupError, subprocess.TimeoutExpired):
                failed = True
        if self.original_default is not None and self.original_search is not None:
            for args in (
                ["security", "default-keychain", "-d", "user", "-s", self.original_default],
                ["security", "list-keychains", "-d", "user", "-s", *self.original_search],
            ):
                try:
                    self.command(args, deadline)
                except (OSError, SetupError, subprocess.TimeoutExpired):
                    failed = True
            if not failed and self.keychain is not None and self.keychain.exists():
                try:
                    self.command(["security", "delete-keychain", str(self.keychain)], deadline)
                except (OSError, SetupError, subprocess.TimeoutExpired):
                    failed = True
        if not failed and self.root is not None:
            shutil.rmtree(self.root)
        if failed:
            raise SetupError("native keyring cleanup failed")


def validate_environment(env: Mapping[str, str], command: Sequence[str]) -> None:
    if env.get("GITHUB_ACTIONS") != "true":
        raise SetupError("CI-only native keyring wrapper refused")
    if env.get("RUNNER_OS") not in ("Linux", "macOS", "Windows"):
        raise SetupError("unsupported CI operating system")
    root = Path(env.get("RUNNER_TEMP", ""))
    if not root.is_absolute() or not root.is_dir() or not command or len(command) > 128:
        raise SetupError("invalid CI command or temporary directory")
    if any(not argument or len(argument) > 8192 or "\0" in argument for argument in command):
        raise SetupError("invalid CI command")


def validate_session_root(root: Path | None, env: Mapping[str, str], in_session: bool) -> None:
    if root is None:
        return
    if (not in_session or env["RUNNER_OS"] != "Linux" or not root.is_absolute()
            or root.is_symlink() or not root.is_dir()
            or root.parent.resolve() != Path(env["RUNNER_TEMP"]).resolve()
            or re.fullmatch(r"mcpjump-keyring-[a-z0-9_]{8}", root.name) is None):
        raise SetupError("invalid owned Linux session directory")


def with_bus(command: Sequence[str], timeout: float, env: Mapping[str, str], executor: Executor,
             cancellation: Cancellation, log: Callable[[str], None]) -> int:
    root = Path(tempfile.mkdtemp(prefix="mcpjump-keyring-", dir=env["RUNNER_TEMP"]))
    root.chmod(0o700)
    child: Child | None = None
    status = 1
    try:
        child = executor.start([
            "dbus-run-session", "--", sys.executable, "-B", "-W", "error", str(Path(__file__).resolve()),
            "--in-session", "--session-root", str(root), "--timeout", str(int(timeout)), "--", *command,
        ], env)
        status = executor.wait(child, timeout + 90, cancellation)
    finally:
        try:
            if child is not None:
                executor.stop(child, 20)
        except (OSError, SetupError, subprocess.TimeoutExpired):
            log("Owned Linux session group cleanup failed; command details omitted.")
            if status == 0:
                status = 1
        if root.exists():
            shutil.rmtree(root)
    return status


def diagnostic(message: str) -> None:
    print(message, file=sys.stderr)


def process_options(grouped: bool) -> dict[str, bool | int]:
    if not grouped:
        return {}
    if os.name != "nt":
        return {"start_new_session": True}
    return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}


def run(command: Sequence[str], timeout: float, env: Mapping[str, str], executor: Executor,
        cancellation: Cancellation, *, in_session: bool = False,
        session_root: Path | None = None,
        log: Callable[[str], None] = diagnostic) -> int:
    validate_environment(env, command)
    validate_session_root(session_root, env, in_session)
    if not math.isfinite(timeout) or not 0 < timeout <= 1500:
        raise SetupError("invalid CI command timeout")
    if env["RUNNER_OS"] == "Linux" and not in_session:
        return with_bus(command, timeout, env, executor, cancellation, log)
    session = NativeSession(dict(env), executor, cancellation, root=session_root)
    grouped = env["RUNNER_OS"] != "Linux"
    child: Child | None = None
    status = 1
    try:
        session.prepare(cancellation)
        if cancellation.number is not None:
            return 128 + cancellation.number
        child = executor.start(command, session.env, grouped=grouped)
        status = executor.wait(child, timeout, cancellation, grouped=grouped)
    except (OSError, SetupError, subprocess.TimeoutExpired, ValueError):
        if cancellation.number is not None:
            status = 128 + cancellation.number
        log("Native keyring setup or command failed; command details omitted.")
    finally:
        cleanup_failed = False
        try:
            if child is not None:
                executor.stop(child, 20, grouped=grouped)
        except (OSError, SetupError, subprocess.TimeoutExpired):
            cleanup_failed = True
        try:
            session.cleanup()
        except (OSError, SetupError, subprocess.TimeoutExpired):
            cleanup_failed = True
        if cleanup_failed:
            log("Owned native keyring cleanup failed; command details omitted.")
            if status == 0:
                status = 1
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", required=True, type=int, choices=(900, 1500))
    parser.add_argument("--in-session", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--session-root", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    environment = dict(os.environ)
    try:
        validate_environment(environment, command)
    except SetupError:
        diagnostic("CI-only native keyring wrapper refused; command details omitted.")
        return 1
    cancellation = Cancellation()

    def cancelled(number: int, _frame: FrameType | None) -> None:
        cancellation.number = number

    previous = {number: signal.signal(number, cancelled) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        return run(command, args.timeout, environment, ProcessExecutor(), cancellation,
                   in_session=args.in_session, session_root=args.session_root)
    except (OSError, SetupError, subprocess.TimeoutExpired):
        print("CI-only native keyring wrapper refused or failed; command details omitted.", file=sys.stderr)
        return 1
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


if __name__ == "__main__":
    sys.exit(main())
