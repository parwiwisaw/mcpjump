// @ts-check
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
export const platforms = Object.freeze([
  Object.freeze({ target: 'aarch64-apple-darwin', os: 'darwin', cpu: 'arm64', extension: '.tar.xz' }),
  Object.freeze({ target: 'x86_64-apple-darwin', os: 'darwin', cpu: 'x64', extension: '.tar.xz' }),
  Object.freeze({ target: 'x86_64-unknown-linux-musl', os: 'linux', cpu: 'x64', extension: '.tar.xz' }),
  Object.freeze({ target: 'aarch64-unknown-linux-musl', os: 'linux', cpu: 'arm64', extension: '.tar.xz' }),
  Object.freeze({ target: 'x86_64-pc-windows-msvc', os: 'win32', cpu: 'x64', extension: '.zip' }),
]);
const MAX_BINARY = 64 * 1024 * 1024;

/** @param {string} filename @param {number} limit */
export function readBounded(filename, limit) {
  const metadata = statSync(filename);
  if (!metadata.isFile() || metadata.size > limit) throw new Error('Invalid or oversized packaging input');
  return readFileSync(filename);
}

/** @param {string} command @param {string[]} args @param {number} limit @param {string=} cwd */
export function checked(command, args, limit, cwd) {
  const result = spawnSync(command, args, {
    cwd, timeout: 30_000, killSignal: 'SIGKILL', maxBuffer: limit,
    env: { ...process.env, npm_config_cache: join(root, 'target/npm-cache') },
  });
  if (result.error || result.status !== 0) throw new Error(`Packaging command failed: ${command}`);
  return result.stdout;
}

/** @param {string} archive */
export function verifyArchive(archive) {
  const checksum = readBounded(`${archive}.sha256`, 4096).toString('utf8').split(/\s+/)[0];
  if (!/^[a-f0-9]{64}$/.test(checksum)) throw new Error('Invalid archive checksum');
  const digest = createHash('sha256').update(readBounded(archive, 128 * 1024 * 1024)).digest('hex');
  if (digest !== checksum) throw new Error('Archive checksum mismatch');
}

/** @param {string} archive @param {string} binary */
export function extractBinary(archive, binary) {
  const unzip = archive.endsWith('.zip') && process.platform !== 'win32';
  const command = unzip ? 'unzip' : 'tar';
  const listArgs = unzip ? ['-Z1', archive] : ['-tf', archive];
  const members = checked(command, listArgs, 64 * 1024).toString('utf8').trim().split(/\r?\n/);
  if (members.length > 32) throw new Error('Too many archive entries');
  const matches = members.filter((name) => name === binary || name.endsWith(`/${binary}`));
  if (matches.length !== 1) throw new Error('Archive must contain exactly one binary');
  const member = matches[0];
  if (/^(?:\/|[A-Za-z]:|-)/.test(member) || member.split('/').includes('..')) throw new Error('Unsafe archive member');
  const args = unzip ? ['-p', archive, member] : ['-xOf', archive, member];
  const bytes = checked(command, args, MAX_BINARY);
  if (bytes.length === 0) throw new Error('Empty release binary');
  return bytes;
}

/** @param {string} directory @param {Record<string, unknown>} manifest */
function initializePackage(directory, manifest) {
  mkdirSync(directory);
  mkdirSync(join(directory, 'bin'));
  writeFileSync(join(directory, 'package.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  for (const filename of ['README.md', 'LICENSE-MIT', 'LICENSE-APACHE']) {
    copyFileSync(join(root, filename), join(directory, filename));
  }
}

/** @param {string} directory @param {string} destination */
function pack(directory, destination) {
  const npm = process.platform === 'win32' ? process.execPath : 'npm';
  const prefix = process.platform === 'win32' ? [join(dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js')] : [];
  checked(npm, [...prefix, 'pack', '--ignore-scripts', '--offline', '--json', '--pack-destination', destination], 1024 * 1024, directory);
}

/** @param {unknown} value @returns {value is Record<string, unknown>} */
function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** @param {unknown} value @param {string} version */
export function validateTemplate(value, version) {
  if (!isRecord(value) || value.name !== 'mcpjump' || value.version !== version || 'scripts' in value
    || typeof value.description !== 'string' || value.license !== 'MIT OR Apache-2.0'
    || !isRecord(value.bin) || value.bin.mcpjump !== 'bin/mcpjump.js'
    || !isRecord(value.repository) || value.repository.type !== 'git'
    || value.repository.url !== 'https://github.com/parwiwisaw/mcpjump'
    || !isRecord(value.engines) || value.engines.node !== '>=22'
    || !isRecord(value.publishConfig) || value.publishConfig.access !== 'public'
    || !Array.isArray(value.files) || value.files.join(',') !== 'bin,README.md,LICENSE-MIT,LICENSE-APACHE'
    || !isRecord(value.optionalDependencies) || Object.keys(value.optionalDependencies).length !== platforms.length) {
    throw new Error('Invalid wrapper package manifest');
  }
  for (const platform of platforms) {
    if (value.optionalDependencies[`@mcpjump/cli-${platform.os}-${platform.cpu}`] !== version) {
      throw new Error('Optional dependency version mismatch');
    }
  }
  return value;
}

/** @param {string[]} args */
export function main(args) {
  if (args.length < 2 || args.length > 3 || !args.slice(0, 2).every(isAbsolute)) {
    throw new Error('Usage: node npm/pack.mjs ABSOLUTE_ARCHIVE_DIR NEW_ABSOLUTE_OUTPUT_DIR [TARGET]');
  }
  const [archives, output, target] = args;
  const selected = target ? platforms.filter((platform) => platform.target === target) : platforms;
  if (selected.length === 0) throw new Error('Unsupported release target');
  const version = readBounded(join(root, 'Cargo.toml'), 64 * 1024).toString('utf8').match(/^version = "([^"]+)"$/m)?.[1];
  if (!version) throw new Error('Missing Cargo package version');
  /** @type {unknown} */
  const parsed = JSON.parse(readBounded(join(root, 'npm/package.json'), 16 * 1024).toString('utf8'));
  const template = validateTemplate(parsed, version);
  mkdirSync(output);
  for (const platform of selected) {
    const name = `@mcpjump/cli-${platform.os}-${platform.cpu}`;
    const archive = join(archives, `mcpjump-${platform.target}${platform.extension}`);
    verifyArchive(archive);
    const binary = platform.os === 'win32' ? 'mcpjump.exe' : 'mcpjump';
    const bytes = extractBinary(archive, binary);
    const directory = join(output, `cli-${platform.os}-${platform.cpu}`);
    initializePackage(directory, {
      name, version, description: template.description, license: template.license,
      repository: template.repository, os: [platform.os], cpu: [platform.cpu],
      files: ['bin', 'README.md', 'LICENSE-MIT', 'LICENSE-APACHE'], publishConfig: { access: 'public' },
    });
    writeFileSync(join(directory, 'bin', binary), bytes, { mode: 0o755 });
    pack(directory, output);
  }
  const wrapper = join(output, 'mcpjump');
  initializePackage(wrapper, template);
  copyFileSync(join(root, 'npm/bin/mcpjump.js'), join(wrapper, 'bin/mcpjump.js'));
  pack(wrapper, output);
  console.log(`Packed ${selected.length} platform package(s) and mcpjump ${version}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(process.argv.slice(2)); }
  catch (error) {
    console.error(error instanceof Error ? error.message : 'Packaging failed');
    process.exitCode = 1;
  }
}
