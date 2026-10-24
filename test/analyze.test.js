'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { parseLockfile } = require('../src/lockfile');
const { analyze } = require('../src/analyze');
const { lock } = require('./_helpers.cjs');

const P = (o) => parseLockfile(lock(o));
const ids = (r) => r.findings.map((f) => f.ruleId).sort();

test('identical lockfiles produce no findings', () => {
  const a = P({ lodash: { version: '4.17.21' } });
  const r = analyze(a, a);
  assert.deepStrictEqual(r.findings, []);
  assert.strictEqual(r.stats.unchanged, 1);
});

test('integrity change on same version is critical (LG001)', () => {
  const r = analyze(P({ chalk: { version: '5.3.0' } }), P({ chalk: { version: '5.3.0', integrity: 'sha512-EVIL' } }));
  assert.deepStrictEqual(ids(r), ['LG001']);
  assert.strictEqual(r.findings[0].severity, 'critical');
});

test('new package with install script (LG004 + LG008)', () => {
  const r = analyze(P({}), P({ evil: { version: '1.0.0', extra: { hasInstallScript: true } } }));
  assert.deepStrictEqual(ids(r), ['LG004', 'LG008']);
});

test('existing package starts running install script on upgrade', () => {
  const r = analyze(P({ dep: { version: '1.0.0' } }), P({ dep: { version: '1.0.1', extra: { hasInstallScript: true } } }));
  assert.deepStrictEqual(ids(r), ['LG004']);
});

test('git and tarball sources are flagged (LG002), git:// insecure (LG003)', () => {
  const r = analyze(P({}), P({
    a: { version: '1.0.0', resolved: 'git+ssh://git@github.com/x/a.git#abc', integrity: null },
    b: { version: '1.0.0', resolved: 'https://evil.example/b.tgz' },
    c: { version: '1.0.0', resolved: 'git://github.com/x/c.git#abc', integrity: null },
  }));
  const non = r.findings.filter((f) => f.ruleId === 'LG002').map((f) => f.package).sort();
  assert.deepStrictEqual(non, ['a', 'b', 'c']);
  assert.ok(r.findings.some((f) => f.ruleId === 'LG003' && f.package === 'c'));
});

test('http registry URL is insecure', () => {
  const r = analyze(null, P({ x: { version: '1.0.0', resolved: 'http://registry.npmjs.org/x/-/x-1.0.0.tgz' } }));
  assert.deepStrictEqual(ids(r), ['LG003']);
});

test('custom registry is allowed with --registry', () => {
  const head = P({ x: { version: '1.0.0', resolved: 'https://npm.corp.local/x/-/x-1.0.0.tgz' } });
  assert.deepStrictEqual(ids(analyze(null, head)), ['LG002']);
  assert.deepStrictEqual(ids(analyze(null, head, { registries: ['https://npm.corp.local'] })), []);
});

test('missing integrity (LG005)', () => {
  const r = analyze(null, P({ x: { version: '1.0.0', integrity: null } }));
  assert.deepStrictEqual(ids(r), ['LG005']);
});

test('source changed for same version (LG006)', () => {
  const r = analyze(P({ x: { version: '1.0.0' } }), P({ x: { version: '1.0.0', resolved: 'https://registry.npmjs.org/x/-/x-1.0.0.tgz?v=2' } }));
  assert.ok(ids(r).includes('LG006'));
});

test('downgrade (LG007)', () => {
  const r = analyze(P({ x: { version: '2.1.0' } }), P({ x: { version: '1.9.9' } }));
  assert.deepStrictEqual(ids(r), ['LG007']);
});

test('tarball name mismatch (LG009)', () => {
  const r = analyze(null, P({ react: { version: '18.0.0', resolved: 'https://registry.npmjs.org/reakt/-/reakt-18.0.0.tgz' } }));
  assert.deepStrictEqual(ids(r), ['LG009']);
});

test('scoped tarball names are parsed correctly', () => {
  const r = analyze(null, P({ '@scope/pkg': { version: '1.0.0', resolved: 'https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz' } }));
  assert.deepStrictEqual(ids(r), []);
});

test('ignore by rule id, rule name, or package', () => {
  const base = P({}); const head = P({ evil: { version: '1.0.0', extra: { hasInstallScript: true } } });
  assert.deepStrictEqual(ids(analyze(base, head, { ignore: ['LG008', 'new-install-script'] })), []);
  assert.deepStrictEqual(ids(analyze(base, head, { ignore: ['evil'] })), []);
});

test('stats count added/removed/changed', () => {
  const r = analyze(P({ a: { version: '1.0.0' }, b: { version: '1.0.0' } }), P({ a: { version: '1.1.0' }, c: { version: '1.0.0' } }));
  assert.deepStrictEqual({ ...r.stats }, { added: 1, removed: 1, changed: 1, unchanged: 0, total: 2 });
});

test('lockfile v1 is parsed including nested deps', () => {
  const v1 = JSON.stringify({ lockfileVersion: 1, dependencies: { a: { version: '1.0.0', resolved: 'https://registry.npmjs.org/a/-/a-1.0.0.tgz', integrity: 'sha512-a', dependencies: { b: { version: '2.0.0', resolved: 'https://registry.npmjs.org/b/-/b-2.0.0.tgz', integrity: 'sha512-b' } } } } });
  const p = parseLockfile(v1);
  assert.deepStrictEqual([...p.packages.keys()], ['node_modules/a', 'node_modules/a/node_modules/b']);
});

test('invalid JSON throws a helpful error', () => {
  assert.throws(() => parseLockfile('{nope', 'x.json'), /x\.json: not valid JSON/);
});
