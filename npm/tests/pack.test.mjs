import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';

const root = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const { checked, extractBinary, main, platforms, readBounded, validateTemplate, verifyArchive } = await import(pathToFileURL(join(root, 'npm/pack.mjs')).href);

function fixture(t, bytes = Buffer.from('release binary')) {
  const directory = mkdtempSync(join(tmpdir(), 'mcpjump-pack-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const staged = join(directory, 'staged');
  mkdirSync(staged);
  writeFileSync(join(staged, 'mcpjump'), bytes);
  const archive = join(directory, 'mcpjump-aarch64-apple-darwin.tar.xz');
  checked('tar', ['-cJf', archive, '-C', staged, 'mcpjump'], 4096);
  const digest = createHash('sha256').update(readFileSync(archive)).digest('hex');
  writeFileSync(`${archive}.sha256`, `${digest}  ${archive}\n`);
  return { directory, archive, bytes };
}

function zipFixture(t, members) {
  const directory = mkdtempSync(join(tmpdir(), 'mcpjump-zip-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const archive = join(directory, 'release.zip');
  const script = 'import json,sys,zipfile\nwith zipfile.ZipFile(sys.argv[1],"w") as z:\n for name in json.loads(sys.argv[2]): z.writestr(name,"release binary")';
  checked('python3', ['-c', script, archive, JSON.stringify(members)], 4096);
  return archive;
}

test('bounded reads accept the exact size and reject an oversized file or directory', (t) => {
  const { directory } = fixture(t);
  const file = join(directory, 'small');
  writeFileSync(file, 'four');
  assert.equal(readBounded(file, 4).toString(), 'four');
  assert.throws(() => readBounded(file, 3), /oversized/);
  assert.throws(() => readBounded(directory, 100), /Invalid/);
});

test('checksum verification accepts the release archive and detects tampering', (t) => {
  const { archive } = fixture(t);
  verifyArchive(archive);
  writeFileSync(archive, 'tampered');
  assert.throws(() => verifyArchive(archive), /checksum mismatch/);
  writeFileSync(`${archive}.sha256`, 'not a checksum');
  assert.throws(() => verifyArchive(archive), /Invalid archive checksum/);
});

test('extraction preserves binary bytes and rejects missing or empty binaries', (t) => {
  const { archive, bytes } = fixture(t);
  assert.deepEqual(extractBinary(archive, 'mcpjump'), bytes);
  assert.throws(() => extractBinary(archive, 'missing'), /exactly one binary/);
  const empty = fixture(t, Buffer.alloc(0));
  assert.throws(() => extractBinary(empty.archive, 'mcpjump'), /Empty release binary/);
});

test('zip extraction preserves bytes and rejects unsafe paths, duplicate binaries and excess entries', (t) => {
  const archive = zipFixture(t, ['release/mcpjump.exe']);
  assert.equal(extractBinary(archive, 'mcpjump.exe').toString(), 'release binary');
  for (const member of ['../mcpjump.exe', '/mcpjump.exe', 'C:/mcpjump.exe', '-x/mcpjump.exe']) {
    assert.throws(() => extractBinary(zipFixture(t, [member]), 'mcpjump.exe'), /Unsafe archive/);
  }
  assert.throws(() => extractBinary(zipFixture(t, ['a/mcpjump.exe', 'b/mcpjump.exe']), 'mcpjump.exe'), /exactly one/);
  const members = ['mcpjump.exe', ...Array.from({ length: 32 }, (_, i) => `file-${i}`)];
  assert.throws(() => extractBinary(zipFixture(t, members), 'mcpjump.exe'), /Too many archive/);
});

test('packaging commands reject failed commands and output overflow', () => {
  assert.throws(() => checked(process.execPath, ['-e', 'process.exit(7)'], 100), /command failed/);
  assert.throws(() => checked(process.execPath, ['-e', 'process.stdout.write("x".repeat(1024))'], 10), /command failed/);
});

test('invalid CLI paths and unknown targets fail before creating packages', () => {
  assert.throws(() => main([]), /Usage/);
  assert.throws(() => main(['relative', '/tmp/unused']), /Usage/);
  assert.throws(() => main(['/tmp/unused', '/tmp/unused2', 'unknown']), /Unsupported/);
  const result = spawnSync(process.execPath, [join(root, 'npm/pack.mjs')], { encoding: 'utf8', timeout: 5000 });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Usage/);
});

test('wrapper manifests reject scripts, missing fields and mismatched platform versions', () => {
  const template = JSON.parse(readFileSync(join(root, 'npm/package.json'), 'utf8'));
  assert.deepEqual(validateTemplate(template, template.version), template);
  for (const invalid of [null, [], {}, { ...template, scripts: {} }, { ...template, bin: null },
    { ...template, optionalDependencies: {} }, { ...template, version: 'wrong' }]) {
    assert.throws(() => validateTemplate(invalid, template.version), /Invalid wrapper/);
  }
  const mismatched = structuredClone(template);
  mismatched.optionalDependencies['@mcpjump/cli-linux-arm64'] = '0.0.0';
  assert.throws(() => validateTemplate(mismatched, template.version), /version mismatch/);
});

test('npm tarballs contain exact release bytes, exact optional versions and no install scripts', { timeout: 30_000 }, (t) => {
  const { directory, archive, bytes } = fixture(t);
  const output = join(directory, 'packages');
  main([directory, output, 'aarch64-apple-darwin']);
  const platform = JSON.parse(readFileSync(join(output, 'cli-darwin-arm64/package.json'), 'utf8'));
  assert.deepEqual(platform.os, ['darwin']);
  assert.deepEqual(platform.cpu, ['arm64']);
  assert.equal(platform.libc, undefined);
  assert.equal(platform.scripts, undefined);
  const tarball = join(output, `mcpjump-cli-darwin-arm64-${platform.version}.tgz`);
  assert.deepEqual(checked('tar', ['-xOf', tarball, 'package/bin/mcpjump'], 1024), bytes);
  const wrapper = JSON.parse(readFileSync(join(output, 'mcpjump/package.json'), 'utf8'));
  assert.equal(wrapper.scripts, undefined);
  assert.equal(Object.keys(wrapper.optionalDependencies).length, 5);
  assert.ok(Object.values(wrapper.optionalDependencies).every((version) => version === platform.version));
  verifyArchive(archive);
});

test('all five platform packages use exact archive bytes and only os/cpu restrictions', { timeout: 30_000 }, (t) => {
  const { directory, archive, bytes } = fixture(t);
  for (const platform of platforms) {
    const filename = join(directory, `mcpjump-${platform.target}${platform.extension}`);
    if (platform.os === 'win32') {
      writeFileSync(filename, readFileSync(zipFixture(t, ['release/mcpjump.exe'])));
    } else if (filename !== archive) {
      writeFileSync(filename, readFileSync(archive));
    }
    writeFileSync(`${filename}.sha256`, createHash('sha256').update(readFileSync(filename)).digest('hex'));
  }
  const output = join(directory, 'all-packages');
  main([directory, output]);
  for (const platform of platforms) {
    const directoryName = `cli-${platform.os}-${platform.cpu}`;
    const manifest = JSON.parse(readFileSync(join(output, directoryName, 'package.json'), 'utf8'));
    assert.deepEqual(manifest.os, [platform.os]);
    assert.deepEqual(manifest.cpu, [platform.cpu]);
    assert.equal(manifest.libc, undefined);
    assert.equal(manifest.scripts, undefined);
    const binary = platform.os === 'win32' ? 'mcpjump.exe' : 'mcpjump';
    const tarball = join(output, `mcpjump-${directoryName}-${manifest.version}.tgz`);
    assert.deepEqual(checked('tar', ['-xOf', tarball, `package/bin/${binary}`], 1024), bytes);
  }
});
