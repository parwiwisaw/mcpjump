#!/usr/bin/env node
// @ts-check
'use strict';

const { spawn } = require('node:child_process');
const { constants } = require('node:os');

/** @param {string} platform @param {string} arch */
function packageName(platform, arch) {
  const supported = ['darwin-arm64', 'darwin-x64', 'linux-x64', 'linux-arm64', 'win32-x64'];
  const pair = `${platform}-${arch}`;
  if (!supported.includes(pair)) throw new Error(`mcpjump does not support ${pair}`);
  return `@mcpjump/cli-${pair}`;
}

/** @param {string} binary @param {string[]} args */
function launch(binary, args) {
  const child = spawn(binary, args, { stdio: 'inherit' });
  /** @type {NodeJS.Signals[]} */
  const signals = ['SIGINT', 'SIGTERM', 'SIGHUP'];
  const handlers = signals.map((signal) => ({ signal, forward: () => { child.kill(signal); } }));
  for (const { signal, forward } of handlers) process.on(signal, forward);
  child.once('error', () => {
    console.error('Could not start mcpjump; reinstall with optional dependencies enabled.');
    process.exitCode = 1;
  });
  child.once('close', (code, signal) => {
    for (const { signal, forward } of handlers) process.removeListener(signal, forward);
    if (signal) {
      process.exitCode = 128 + constants.signals[signal];
      process.kill(process.pid, signal);
    } else {
      process.exitCode = code === null || code < 0 ? 1 : code;
    }
  });
}

function main() {
  let name;
  try {
    name = packageName(process.platform, process.arch);
  } catch (error) {
    console.error(error instanceof Error ? error.message : 'Unsupported mcpjump platform');
    process.exitCode = 1;
    return;
  }
  const executable = process.platform === 'win32' ? 'mcpjump.exe' : 'mcpjump';
  let binary;
  try {
    binary = require.resolve(`${name}/bin/${executable}`);
  } catch {
    console.error(`Missing ${name}. Reinstall mcpjump with optional dependencies enabled; install scripts are not required.`);
    process.exitCode = 1;
    return;
  }
  launch(binary, process.argv.slice(2));
}

module.exports = { packageName, launch, main };
if (require.main === module) main();
