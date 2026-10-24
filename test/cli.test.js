'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { main } = require('../src/cli');
const { lock } = require('./_helpers.cjs');

function run(args, cwd) {
  let out = ''; let err = '';
  const prev = process.cwd(); if (cwd) process.chdir(cwd);
  try {
    const code = main(args, { stdout: { write: (s) => { out += s; } }, stderr: { write: (s) => { err += s; } } });
    return { code, out, err };
  } finally { process.chdir(prev); }
}

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'lockgate-')); }

test('--help and --version', () => {
  assert.match(run(['--help']).out, /Usage:/);
  assert.match(run(['--version']).out, /^\d+\.\d+\.\d+/);
});

test('bad option exits 2', () => {
  assert.strictEqual(run(['--wat']).code, 2);
  assert.strictEqual(run(['--format', 'xml']).code, 2);
});

test('file vs file: critical finding exits 1, json output', () => {
  const d = tmp();
  fs.writeFileSync(path.join(d, 'base.json'), lock({ x: { version: '1.0.0' } }));
  fs.writeFileSync(path.join(d, 'package-lock.json'), lock({ x: { version: '1.0.0', integrity: 'sha512-other' } }));
  const r = run(['--base', 'base.json', '--format', 'json'], d);
  assert.strictEqual(r.code, 1);
  const j = JSON.parse(r.out);
  assert.strictEqual(j.findings[0].ruleId, 'LG001');
});

test('additions alone do not fail at default threshold', () => {
  const d = tmp();
  fs.writeFileSync(path.join(d, 'base.json'), lock({}));
  fs.writeFileSync(path.join(d, 'package-lock.json'), lock({ x: { version: '1.0.0' } }));
  assert.strictEqual(run(['-b', 'base.json'], d).code, 0);
  assert.strictEqual(run(['-b', 'base.json', '--fail-on', 'info'], d).code, 1);
});

test('sarif output is valid 2.1.0 shape', () => {
  const d = tmp();
  fs.writeFileSync(path.join(d, 'package-lock.json'), lock({ x: { version: '1.0.0', resolved: 'https://evil.example/x.tgz' } }));
  const r = run(['--format', 'sarif', '--no-color'], d);
  const s = JSON.parse(r.out);
  assert.strictEqual(s.version, '2.1.0');
  assert.strictEqual(s.runs[0].results[0].ruleId, 'LG002');
  assert.strictEqual(s.runs[0].tool.driver.rules[0].id, 'LG002');
});

test('git ref as base', () => {
  const d = tmp();
  const g = (...a) => execFileSync('git', a, { cwd: d, stdio: 'pipe' });
  g('init', '-q'); g('config', 'user.email', 't@t'); g('config', 'user.name', 't');
  fs.writeFileSync(path.join(d, 'package-lock.json'), lock({ x: { version: '1.0.0' } }));
  g('add', '.'); g('commit', '-qm', 'base');
  fs.writeFileSync(path.join(d, 'package-lock.json'), lock({ x: { version: '1.0.0' }, y: { version: '1.0.0', extra: { hasInstallScript: true } } }));
  const r = run(['--base', 'HEAD', '--no-color'], d);
  assert.strictEqual(r.code, 1);
  assert.match(r.out, /LG004 new package y@1.0.0 runs an install script/);
});

test('missing head lockfile exits 2', () => {
  assert.strictEqual(run(['does-not-exist.json']).code, 2);
});
