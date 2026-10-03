"""Exercise the generated release shell commands with harmless command stubs."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from normalize_dist_workflow import read_bounded

ROOT = Path(__file__).resolve().parents[1]
STUBS = """set -eo pipefail
dist() { printf '%s\\0' "$@" >> "$CALLS"; printf '{}\\n'; }
gh() { printf '%s\\0' "$@" >> "$CALLS"; }
jq() { printf '{}\\n'; }
"""


def run_step(marker: str) -> str:
    text = read_bounded(ROOT / '.github/workflows/release.yml')
    if text.count(marker) != 1:
        raise ValueError('Release step marker changed')
    remaining = text.split(marker, 1)[1]
    lines = remaining.splitlines()
    body: list[str] = []
    for line in lines[:1024]:
        if line and not line.startswith('          '):
            break
        body.append(line[10:])
    script = '\n'.join(body)
    if not script or len(script) > 8192:
        raise ValueError('Release step exceeds its bound')
    return script.replace('${{ matrix.dist_args }}', '--artifacts=local')


def execute(script: str, tag: str) -> tuple[int, list[str], bool]:
    with tempfile.TemporaryDirectory(prefix='mcpjump-tags-') as directory:
        root = Path(directory)
        calls = root / 'calls'
        environment = {
            **os.environ,
            'CALLS': str(calls),
            'RELEASE_TAG': tag,
            'GITHUB_OUTPUT': str(root / 'output'),
            'BUILD_MANIFEST_NAME': str(root / 'build-manifest.json'),
            'RUNNER_TEMP': directory,
            'ANNOUNCEMENT_BODY': 'Release notes',
            'ANNOUNCEMENT_TITLE': 'Release',
            'RELEASE_COMMIT': 'test-commit',
            'PRERELEASE_FLAG': '',
        }
        result = subprocess.run(
            ['bash', '--noprofile', '--norc', '-c', STUBS + script],
            cwd=directory, env=environment, capture_output=True, check=False, timeout=5,
        )
        arguments = calls.read_bytes().decode().rstrip('\0').split('\0') if calls.exists() else []
        return result.returncode, arguments, (root / 'injected').exists()


class ReleaseTagTests(unittest.TestCase):
    def test_plan_rejects_unsafe_tags_before_hosting(self) -> None:
        script = run_step('      - id: plan\n        run: |\n')
        for tag in [
            'v0.1.0;touch${IFS}injected;#',
            'v0.1.0$(touch injected)',
            'v0.1.0";touch injected;#',
            'v0.1.0\ntouch injected',
            'v0.1.0' + 'a' * 256,
        ]:
            with self.subTest(tag=tag):
                status, calls, injected = execute(script, tag)
                self.assertNotEqual(status, 0)
                self.assertEqual(calls, [])
                self.assertFalse(injected)

    def test_plan_preserves_valid_tags_and_pr_planning(self) -> None:
        script = run_step('      - id: plan\n        run: |\n')
        for tag in ['v0.1.0', 'mcpjump/0.1.0', 'releases/v0.1.0-rc.1+build', 'v0.1.0' + 'a' * 250, '']:
            with self.subTest(tag=tag):
                status, calls, injected = execute(script, tag)
                self.assertEqual(status, 0)
                expected = ['host', '--steps=create', '--tag=' + tag, '--output-format=json'] if tag else ['plan', '--output-format=json']
                self.assertEqual(calls, expected)
                self.assertFalse(injected)

    def test_downstream_commands_pass_tags_as_one_argument(self) -> None:
        markers = [
            '      - name: Build artifacts\n        shell: bash\n        run: |\n',
            '      - id: cargo-dist\n        shell: bash\n        run: |\n',
            '      - id: host\n        shell: bash\n        run: |\n',
            '          RELEASE_COMMIT: "${{ github.sha }}"\n        run: |\n',
        ]
        tag = 'v0.1.0";touch${IFS}injected;#$(touch injected)'
        for marker in markers:
            with self.subTest(marker=marker):
                status, calls, injected = execute(run_step(marker), tag)
                self.assertEqual(status, 0)
                self.assertTrue(tag in calls or '--tag=' + tag in calls)
                self.assertFalse(injected)


if __name__ == '__main__':
    unittest.main()
