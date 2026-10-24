'use strict';
const fs = require('fs');
const { execFileSync } = require('child_process');
const { parseLockfile } = require('./lockfile');
const { analyze } = require('./analyze');
const { toText, toJSON, toSARIF } = require('./report');
const { RULES, sevRank, SEVERITY_ORDER } = require('./rules');
const { version } = require('../package.json');

const HELP = `lockgate ${version} - offline npm lockfile diff gate for pull requests

Usage:
  lockgate [options] [head-lockfile]
  lockgate --base <ref|file> [head-lockfile]

Compares package-lock.json between a base (git ref or file) and the current
version and flags supply-chain red flags: changed integrity hashes, git/tarball
sources, new install scripts, insecure protocols, downgrades. Without --base it
audits a single lockfile. Never touches the network.

Options:
  -b, --base <ref|file>   git ref (e.g. origin/main) or path to the base lockfile
  -f, --format <fmt>      text (default), json, sarif
  -o, --output <file>     write report to a file instead of stdout
  --fail-on <severity>    exit 1 at/above: info|low|medium|high|critical (default: high)
  --registry <url>        allowed registry (repeatable; default https://registry.npmjs.org/)
  --ignore <id|pkg>       ignore a rule id, rule name, or package name (repeatable)
  --list-install-scripts  in single-file mode, list every package with an install script
  --rules                 print the rule catalog and exit
  --no-color              disable colors
  -h, --help              show help
  -v, --version           show version

Exit codes: 0 ok, 1 findings at/above --fail-on, 2 usage or parse error.`;

function parseArgs(argv) {
  const o = { format: 'text', failOn: 'high', registries: [], ignore: [], color: process.stdout.isTTY, head: 'package-lock.json' };
  const need = (i) => { if (argv[i + 1] === undefined) throw new Error(`${argv[i]} needs a value`); return argv[i + 1]; };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '-h': case '--help': o.help = true; break;
      case '-v': case '--version': o.version = true; break;
      case '-b': case '--base': o.base = need(i); i++; break;
      case '-f': case '--format': o.format = need(i); i++; break;
      case '-o': case '--output': o.output = need(i); i++; break;
      case '--fail-on': o.failOn = need(i); i++; break;
      case '--registry': o.registries.push(need(i)); i++; break;
      case '--ignore': o.ignore.push(need(i)); i++; break;
      case '--list-install-scripts': o.listInstallScripts = true; break;
      case '--rules': o.rules = true; break;
      case '--no-color': o.color = false; break;
      default:
        if (a.startsWith('-')) throw new Error(`unknown option ${a}`);
        o.head = a;
    }
  }
  if (!['text', 'json', 'sarif'].includes(o.format)) throw new Error(`unknown format ${o.format}`);
  if (!SEVERITY_ORDER.includes(o.failOn)) throw new Error(`unknown severity ${o.failOn}`);
  return o;
}

function readBase(base, headPath) {
  if (fs.existsSync(base) && fs.statSync(base).isFile()) return fs.readFileSync(base, 'utf8');
  // Treat as a git ref; read the lockfile at that ref (local git only, no fetch).
  try {
    return execFileSync('git', ['show', `${base}:./${headPath}`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 256 * 1024 * 1024 });
  } catch (e) {
    const err = String(e.stderr || '');
    if (/does not exist|exists on disk, but not in/.test(err)) return null; // lockfile is new in this PR
    throw new Error(`could not read ${headPath} at "${base}": ${err.trim() || e.message}`);
  }
}

function main(argv, io = { stdout: process.stdout, stderr: process.stderr }) {
  let o;
  try { o = parseArgs(argv); } catch (e) { io.stderr.write(`lockgate: ${e.message}\n`); return 2; }
  if (o.help) { io.stdout.write(`${HELP}\n`); return 0; }
  if (o.version) { io.stdout.write(`${version}\n`); return 0; }
  if (o.rules) {
    for (const r of Object.values(RULES)) io.stdout.write(`${r.id}  ${r.severity.padEnd(8)} ${r.name}\n    ${r.help}\n`);
    return 0;
  }
  try {
    const head = parseLockfile(fs.readFileSync(o.head, 'utf8'), o.head);
    let base = null;
    if (o.base) {
      const text = readBase(o.base, o.head);
      base = text === null ? { packages: new Map() } : parseLockfile(text, `${o.base}:${o.head}`);
    }
    const result = analyze(base, head, o);
    const out = o.format === 'json' ? toJSON(result) : o.format === 'sarif' ? toSARIF(result, o.head) : toText(result, { color: o.color && !o.output });
    if (o.output) fs.writeFileSync(o.output, `${out}\n`); else io.stdout.write(`${out}\n`);
    const fail = result.findings.some((f) => sevRank(f.severity) >= sevRank(o.failOn) && !(f.ruleId === 'LG008' && o.failOn !== 'info'));
    return fail ? 1 : 0;
  } catch (e) {
    io.stderr.write(`lockgate: ${e.message}\n`);
    return 2;
  }
}

module.exports = { main, parseArgs };
