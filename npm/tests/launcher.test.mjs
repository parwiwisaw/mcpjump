import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';

const root = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const launcher = join(root, 'npm/bin/mcpjump.js');
const { packageName } = createRequire(import.meta.url)(launcher);
const { platforms } = await import(pathToFileURL(join(root, 'npm/pack.mjs')).href);

test('every release platform resolves to the exact optional package', () => {
  for (const platform of platforms) {
    assert.equal(packageName(platform.os, platform.cpu), `@mcpjump/cli-${platform.os}-${platform.cpu}`);
  }
  assert.throws(() => packageName('win32', 'arm64'), /does not support win32-arm64/);
  assert.throws(() => packageName('freebsd', 'x64'), /does not support/);
});

test('missing platform package gives actionable stderr and no stdout', () => {
  const result = spawnSync(process.execPath, [launcher, '--version'], { encoding: 'utf8', timeout: 5000 });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /Missing @mcpjump\/cli-/);
  assert.match(result.stderr, /optional dependencies enabled/);
});

test('launcher passes arguments, stdin, stdout, stderr and a nonzero exit unchanged', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'mcpjump-launcher-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const fixture = join(directory, 'fixture.cjs');
  writeFileSync(fixture, 'const fs=require("node:fs"); process.stdout.write(JSON.stringify({args:process.argv.slice(2),stdin:fs.readFileSync(0,"utf8")})); process.stderr.write("fixture error"); process.exitCode=7;');
  const code = `require(${JSON.stringify(launcher)}).launch(process.execPath, process.argv.slice(1))`;
  const result = spawnSync(process.execPath, ['-e', code, fixture, 'with spaces', "O'Brien", '${literal}'], {
    encoding: 'utf8', input: 'stdin value\n', timeout: 5000,
  });
  assert.equal(result.status, 7);
  assert.deepEqual(JSON.parse(result.stdout), { args: ['with spaces', "O'Brien", '${literal}'], stdin: 'stdin value\n' });
  assert.equal(result.stderr, 'fixture error');
});

test('child execution failure reports failure', () => {
  const code = `require(${JSON.stringify(launcher)}).launch("/mcpjump-missing-executable", [])`;
  const result = spawnSync(process.execPath, ['-e', code], { encoding: 'utf8', timeout: 5000 });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Could not start mcpjump/);
});

test('SIGINT reaches the child and its termination signal reaches the caller', { skip: process.platform === 'win32', timeout: 5000 }, async (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'mcpjump-signal-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const fixture = join(directory, 'fixture.cjs');
  writeFileSync(fixture, 'process.stdout.write("ready\\n"); setInterval(()=>{}, 1000);');
  const code = `require(${JSON.stringify(launcher)}).launch(process.execPath, [${JSON.stringify(fixture)}])`;
  const wrapper = spawn(process.execPath, ['-e', code], { stdio: ['ignore', 'pipe', 'pipe'] });
  t.after(() => { if (wrapper.exitCode === null && wrapper.signalCode === null) wrapper.kill('SIGKILL'); });
  await once(wrapper.stdout, 'data');
  const exited = once(wrapper, 'exit');
  wrapper.kill('SIGINT');
  const [status, signal] = await exited;
  assert.equal(status, null);
  assert.equal(signal, 'SIGINT');
});
