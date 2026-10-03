"""Pinned installer boundary tests; no network, global tools or executable runs."""

import hashlib
import io
import lzma
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest
import zipfile

from install_cargo_dist import (
    ARCHIVES, MAX_COMPRESSED, MAX_DECODED, MAX_MEMBERS, Archive, InstallError,
    checked_member, executable_bytes, host_target, install, read_executable,
    runner_paths, verify_archive,
)


def tar_bundle(root: Path, entries: list[tuple[str, bytes, bytes]]) -> Archive:
    path = root / "fixture.tar.xz"
    with tarfile.open(path, "w:xz") as bundle:
        for name, kind, data in entries:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.mode = 0o755
            member.size = len(data) if kind == tarfile.REGTYPE else 0
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                member.linkname = "dist"
            bundle.addfile(member, io.BytesIO(data) if member.isfile() else None)
    return Archive(path.name, hashlib.sha256(path.read_bytes()).hexdigest(), "host/dist")


def zip_bundle(root: Path, entries: list[tuple[str, int, bytes]]) -> Archive:
    path = root / "fixture.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for name, mode, data in entries:
            member = zipfile.ZipInfo(name)
            member.create_system = 3
            member.external_attr = mode << 16
            bundle.writestr(member, data)
    return Archive(path.name, hashlib.sha256(path.read_bytes()).hexdigest(), "dist.exe")


class InstallerTests(unittest.TestCase):
    def test_all_supported_hosts_select_native_host_tools(self) -> None:
        cases = [
            ("Darwin", "arm64", "aarch64-apple-darwin"),
            ("Darwin", "x86_64", "x86_64-apple-darwin"),
            ("Linux", "x86_64", "x86_64-unknown-linux-gnu"),
            ("Linux", "aarch64", "aarch64-unknown-linux-gnu"),
            ("Windows", "AMD64", "x86_64-pc-windows-msvc"),
        ]
        for system, machine, target in cases:
            with self.subTest(system=system, machine=machine):
                self.assertEqual(host_target(system, machine), target)
                self.assertIn(target, ARCHIVES)
        for system, machine in [("Windows", "arm64"), ("Linux", "i686"), ("Other", "x86_64")]:
            with self.assertRaises(InstallError):
                host_target(system, machine)

    def test_runner_refusal_and_path_validation_precede_installation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path_file = root / "path"
            path_file.touch()
            env = {"GITHUB_ACTIONS": "true", "RUNNER_TEMP": str(root),
                   "GITHUB_PATH": str(path_file)}
            self.assertEqual(runner_paths(env), (root, path_file))
            for change in [{"GITHUB_ACTIONS": "false"}, {"RUNNER_TEMP": ""},
                           {"RUNNER_TEMP": "relative"}, {"GITHUB_PATH": "missing"},
                           {"GITHUB_PATH": str(path_file) + "\nextra"},
                           {"GITHUB_PATH": str(path_file) + "\0extra"}]:
                with self.subTest(change=change), self.assertRaises(InstallError):
                    runner_paths({**env, **change})
            self.assertEqual(list(root.iterdir()), [path_file])

    def test_checksum_is_checked_before_archive_decoding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "broken.tar.xz"
            path.write_bytes(b"not an archive")
            pin = Archive(path.name, "0" * 64, "dist")
            with self.assertRaisesRegex(InstallError, "checksum mismatch"):
                executable_bytes(pin, path)

    def test_compressed_size_rejects_empty_and_over_limit_without_decoding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "archive"
            for size in (0, MAX_COMPRESSED + 1):
                with path.open("wb") as stream:
                    stream.truncate(size)
                with self.assertRaisesRegex(InstallError, "compressed archive"):
                    verify_archive(Archive(path.name, "0" * 64, "dist"), path)
            with path.open("wb") as stream:
                stream.truncate(MAX_COMPRESSED)
            pin = Archive(path.name, hashlib.sha256(path.read_bytes()).hexdigest(), "dist")
            verify_archive(pin, path)

    def test_member_and_decoded_bounds_accept_exact_limits(self) -> None:
        self.assertEqual(checked_member("host/dist", MAX_DECODED, MAX_MEMBERS - 1, 0),
                         MAX_DECODED)
        for size, index, total in [(1, MAX_MEMBERS, 0), (MAX_DECODED + 1, 0, 0),
                                   (1, 0, MAX_DECODED), (-1, 0, 0)]:
            with self.assertRaises(InstallError):
                checked_member("host/dist", size, index, total)

    def test_traversal_absolute_and_windows_paths_are_rejected(self) -> None:
        for name in ("../dist", "/dist", "host/../dist", "host//dist", "host/./dist",
                     "C:/dist.exe", "host\\dist", "dist\0", "dist\nextra"):
            with self.subTest(name=name), self.assertRaises(InstallError):
                checked_member(name, 1, 0, 0)

    def test_executable_length_is_checked_and_empty_or_oversized_is_rejected(self) -> None:
        self.assertEqual(read_executable(io.BytesIO(b"data"), 4), b"data")
        for data, size in [(b"short", 6), (b"extra", 4), (b"", 0), (b"", MAX_DECODED + 1)]:
            with self.assertRaises(InstallError):
                read_executable(io.BytesIO(data), size)

    def test_tar_extracts_only_exact_regular_executable_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pin = tar_bundle(root, [("host", tarfile.DIRTYPE, b""),
                                    ("host/README", tarfile.REGTYPE, b"documentation"),
                                    ("host/dist", tarfile.REGTYPE, b"binary")])
            self.assertEqual(executable_bytes(pin, root / pin.filename), b"binary")
            self.assertEqual([p.name for p in root.iterdir()], [pin.filename])

    def test_tar_rejects_links_devices_missing_and_duplicate_executables(self) -> None:
        cases = [
            [("host/dist", tarfile.SYMTYPE, b"")],
            [("host/dist", tarfile.LNKTYPE, b"")],
            [("host/device", tarfile.CHRTYPE, b"")],
            [("other/dist", tarfile.REGTYPE, b"binary")],
            [("host/dist", tarfile.REGTYPE, b"one"), ("host/dist", tarfile.REGTYPE, b"two")],
            [("host/dist", tarfile.REGTYPE, b"binary"), ("../late", tarfile.REGTYPE, b"x")],
        ]
        for entries in cases:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                pin = tar_bundle(root, entries)
                with self.assertRaises(InstallError):
                    executable_bytes(pin, root / pin.filename)

    def test_tar_rejects_member_count_and_declared_decode_overflow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pin = tar_bundle(root, [("host/dist", tarfile.REGTYPE, b"binary")]
                             + [(f"host/doc-{n}", tarfile.REGTYPE, b"x")
                                for n in range(MAX_MEMBERS - 1)])
            self.assertEqual(executable_bytes(pin, root / pin.filename), b"binary")
            pin = tar_bundle(root, [(f"host/doc-{n}", tarfile.REGTYPE, b"x")
                                    for n in range(MAX_MEMBERS + 1)])
            with self.assertRaisesRegex(InstallError, "limit"):
                executable_bytes(pin, root / pin.filename)
            path = root / "huge.tar.xz"
            member = tarfile.TarInfo("host/dist")
            member.size = MAX_DECODED + 1
            path.write_bytes(lzma.compress(member.tobuf() + b"\0" * 1024))
            pin = Archive(path.name, hashlib.sha256(path.read_bytes()).hexdigest(), "host/dist")
            with self.assertRaisesRegex(InstallError, "limit"):
                executable_bytes(pin, path)

    def test_zip_accepts_flat_windows_executable_and_rejects_links_or_wrong_name(self) -> None:
        cases = [
            [("dist.exe", stat.S_IFREG | 0o644, b"windows binary")],
            [("dist.exe", stat.S_IFLNK | 0o777, b"target")],
            [("other.exe", stat.S_IFREG | 0o644, b"binary")],
            [("dist.exe", stat.S_IFREG | 0o644, b"binary"),
             ("../late", stat.S_IFREG | 0o644, b"unsafe")],
        ]
        for number, entries in enumerate(cases):
            with self.subTest(number=number), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                pin = zip_bundle(root, entries)
                if number == 0:
                    self.assertEqual(executable_bytes(pin, root / pin.filename), b"windows binary")
                else:
                    with self.assertRaises(InstallError):
                        executable_bytes(pin, root / pin.filename)

    def test_zip_rejects_member_count_overflow(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pin = zip_bundle(root, [(f"doc-{n}", stat.S_IFREG | 0o644, b"x")
                                    for n in range(MAX_MEMBERS + 1)])
            with self.assertRaisesRegex(InstallError, "member limit"):
                executable_bytes(pin, root / pin.filename)

    def test_zip_rejects_duplicate_exact_executable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pin = zip_bundle(root, [("dist.exe", stat.S_IFREG | 0o644, b"one"),
                                    ("fake.exe", stat.S_IFREG | 0o644, b"two")])
            path = root / pin.filename
            # Equal-length header renaming makes a duplicate without suppressing warnings.
            path.write_bytes(path.read_bytes().replace(b"fake.exe", b"dist.exe"))
            pin = Archive(path.name, hashlib.sha256(path.read_bytes()).hexdigest(), "dist.exe")
            with self.assertRaisesRegex(InstallError, "duplicate executable"):
                executable_bytes(pin, path)

    def test_install_writes_only_binary_then_appends_owned_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "runner"
            root.mkdir()
            path_file = base / "path"
            path_file.write_text("prior\n")
            pin = tar_bundle(base, [("host/dist", tarfile.REGTYPE, b"binary")])

            def fixture_download(archive: Archive, destination: Path) -> None:
                shutil.copyfile(base / archive.filename, destination)

            binary = install(pin, root, path_file, fixture_download)
            self.assertEqual(binary.read_bytes(), b"binary")
            self.assertEqual([p.name for p in binary.parent.iterdir()], ["dist"])
            self.assertEqual(path_file.read_text(), "prior\n" + str(binary.parent) + "\n")
            self.assertEqual(binary.parent.parent, root)
            if os.name != "nt":
                self.assertTrue(binary.stat().st_mode & stat.S_IXUSR)

    def test_failed_checksum_or_transport_cleans_owned_dir_without_path_update(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "runner"
            root.mkdir()
            path_file = Path(directory) / "path"
            path_file.write_text("prior\n")
            pin = Archive("fixture.tar.xz", "0" * 64, "host/dist")

            def bad_download(archive: Archive, destination: Path) -> None:
                destination.write_bytes(b"corrupt")

            def timed_out(archive: Archive, destination: Path) -> None:
                raise subprocess.TimeoutExpired("bounded curl", 100)

            for downloader in (bad_download, timed_out):
                with self.assertRaises((InstallError, subprocess.TimeoutExpired)):
                    install(pin, root, path_file, downloader)
                self.assertEqual(list(root.iterdir()), [])
                self.assertEqual(path_file.read_text(), "prior\n")


if __name__ == "__main__":
    unittest.main()
