"""Install the verified cargo-dist host archive into a GitHub runner's temp dir."""

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import BinaryIO, Callable, Mapping
import zipfile


VERSION = "0.33.0"
RELEASE_URL = f"https://github.com/axodotdev/cargo-dist/releases/download/v{VERSION}/"
MAX_COMPRESSED = 16 * 1024 * 1024
MAX_DECODED = 64 * 1024 * 1024
MAX_MEMBERS = 64


class InstallError(Exception):
    """A pinned artifact or owned runner directory failed validation."""


@dataclass(frozen=True)
class Archive:
    filename: str
    sha256: str
    executable: str


# GitHub v0.33.0 asset digests and dist-manifest.json agree with these pins.
ARCHIVES = {
    "aarch64-apple-darwin": Archive(
        "cargo-dist-aarch64-apple-darwin.tar.xz",
        "7b3cbe25511de01d74c0f5fcb7909edabd379bea9cfa284d93af5a3cdfa3247c",
        "cargo-dist-aarch64-apple-darwin/dist",
    ),
    "x86_64-apple-darwin": Archive(
        "cargo-dist-x86_64-apple-darwin.tar.xz",
        "6a49bfb61bd86770d79c27f3d2b40c6b2e71cde940d3d31a6ccaaffc124d7a29",
        "cargo-dist-x86_64-apple-darwin/dist",
    ),
    "x86_64-unknown-linux-gnu": Archive(
        "cargo-dist-x86_64-unknown-linux-gnu.tar.xz",
        "4b3f0a5f0ebbdb798f6db649d01b32ba1518376b6f7a0502b7d92b75cc2c8293",
        "cargo-dist-x86_64-unknown-linux-gnu/dist",
    ),
    "aarch64-unknown-linux-gnu": Archive(
        "cargo-dist-aarch64-unknown-linux-gnu.tar.xz",
        "9c554ab21a58ad46eb9b6710f89633ccb26bc2577cf4b0c2d18a5b826a31913e",
        "cargo-dist-aarch64-unknown-linux-gnu/dist",
    ),
    "x86_64-pc-windows-msvc": Archive(
        "cargo-dist-x86_64-pc-windows-msvc.zip",
        "9a36d70795e14326a5ec4bf17aee085df00ab85a322739291ea5d4b1b5f693cd",
        "dist.exe",
    ),
}


def host_target(system: str, machine: str) -> str:
    cpu = {"arm64": "aarch64", "aarch64": "aarch64",
           "x86_64": "x86_64", "amd64": "x86_64"}.get(machine.lower())
    suffix = {"Darwin": "apple-darwin", "Linux": "unknown-linux-gnu",
              "Windows": "pc-windows-msvc"}.get(system)
    target = f"{cpu}-{suffix}"
    if target not in ARCHIVES:
        raise InstallError("unsupported cargo-dist host")
    return target


def runner_paths(env: Mapping[str, str]) -> tuple[Path, Path]:
    if env.get("GITHUB_ACTIONS") != "true":
        raise InstallError("GitHub runner required")
    for name in ("RUNNER_TEMP", "GITHUB_PATH"):
        value = env.get(name, "")
        if not value or len(value) > 4096 or any(c in value for c in "\0\r\n"):
            raise InstallError("invalid runner path")
    root, path_file = Path(env["RUNNER_TEMP"]), Path(env["GITHUB_PATH"])
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise InstallError("invalid runner temporary directory")
    if not path_file.is_absolute() or not path_file.is_file() or path_file.is_symlink():
        raise InstallError("invalid runner PATH file")
    return root, path_file


def download(archive: Archive, destination: Path) -> None:
    subprocess.run([
        "curl", "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2",
        "--fail", "--location", "--silent", "--show-error", "--retry", "0",
        "--connect-timeout", "15", "--max-time", "90", "--max-redirs", "5",
        "--max-filesize", str(MAX_COMPRESSED), "--output", str(destination),
        RELEASE_URL + archive.filename,
    ], check=True, timeout=100, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def verify_archive(archive: Archive, path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_COMPRESSED:
        raise InstallError("invalid compressed archive")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for _ in range(MAX_COMPRESSED // 65536 + 1):
            block = stream.read(65536)
            if not block:
                break
            digest.update(block)
        else:
            raise InstallError("compressed archive exceeds limit")
    if digest.hexdigest() != archive.sha256:
        raise InstallError("cargo-dist checksum mismatch")


def checked_member(name: str, size: int, index: int, total: int) -> int:
    parts = name.removesuffix("/").split("/")
    if (not name or len(name) > 4096 or PurePosixPath(name).is_absolute()
            or any(part in ("", ".", "..") for part in parts)
            or any(c in name for c in "\\:\0\r\n")):
        raise InstallError("unsafe archive member path")
    if index >= MAX_MEMBERS or size < 0 or total + size > MAX_DECODED:
        raise InstallError("archive exceeds member or decoded size limit")
    return total + size


def read_executable(stream: BinaryIO, size: int) -> bytes:
    if not 0 < size <= MAX_DECODED:
        raise InstallError("invalid executable size")
    data = stream.read(size + 1)
    if len(data) != size:
        raise InstallError("executable size mismatch")
    return data


def tar_executable(archive: Archive, path: Path) -> bytes:
    data: bytes | None = None
    total = 0
    with tarfile.open(path, "r:xz") as bundle:
        for index, member in enumerate(bundle):
            total = checked_member(member.name, member.size, index, total)
            if not (member.isfile() or member.isdir()):
                raise InstallError("archive contains nonregular member")
            if member.name != archive.executable:
                continue
            if not member.isfile() or not member.mode & 0o111 or data is not None:
                raise InstallError("invalid or duplicate executable")
            stream = bundle.extractfile(member)
            if stream is None:
                raise InstallError("executable missing")
            with stream:
                data = read_executable(stream, member.size)
    if data is None:
        raise InstallError("executable missing")
    return data


def zip_executable(archive: Archive, path: Path) -> bytes:
    data: bytes | None = None
    total = 0
    with zipfile.ZipFile(path) as bundle:
        members = bundle.infolist()
        if len(members) > MAX_MEMBERS:
            raise InstallError("archive exceeds member limit")
        for index, member in enumerate(members):
            total = checked_member(member.filename, member.file_size, index, total)
            mode = stat.S_IFMT(member.external_attr >> 16)
            if mode not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise InstallError("archive contains nonregular member")
            if member.filename != archive.executable:
                continue
            if member.is_dir() or mode == stat.S_IFDIR or data is not None:
                raise InstallError("invalid or duplicate executable")
            with bundle.open(member) as stream:
                data = read_executable(stream, member.file_size)
    if data is None:
        raise InstallError("executable missing")
    return data


def executable_bytes(archive: Archive, path: Path) -> bytes:
    verify_archive(archive, path)
    if archive.filename.endswith(".tar.xz"):
        return tar_executable(archive, path)
    if archive.filename.endswith(".zip"):
        return zip_executable(archive, path)
    raise InstallError("unsupported archive format")


def install(archive: Archive, root: Path, path_file: Path,
            downloader: Callable[[Archive, Path], None] = download) -> Path:
    directory = Path(tempfile.mkdtemp(prefix="mcpjump-cargo-dist-", dir=root))
    directory.chmod(0o700)
    complete = False
    try:
        packed = directory / archive.filename
        downloader(archive, packed)
        data = executable_bytes(archive, packed)
        packed.unlink()
        binary = directory / PurePosixPath(archive.executable).name
        with binary.open("xb") as stream:
            stream.write(data)
        binary.chmod(0o755)
        with path_file.open("a", encoding="utf-8") as stream:
            stream.write(str(directory) + "\n")
        complete = True
        return binary
    finally:
        if not complete:
            shutil.rmtree(directory)


def main() -> int:
    try:
        target = host_target(platform.system(), platform.machine())
        root, path_file = runner_paths(os.environ)
        install(ARCHIVES[target], root, path_file)
    except (InstallError, OSError, subprocess.SubprocessError, tarfile.TarError,
            zipfile.BadZipFile, ValueError):
        print("Pinned cargo-dist installation failed; runner or archive validation failed.",
              file=sys.stderr)
        return 1
    print(f"Installed cargo-dist {VERSION} for host {target} in owned runner temporary storage.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
