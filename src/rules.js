'use strict';

const DEFAULT_REGISTRIES = ['https://registry.npmjs.org/'];

const RULES = {
  'LG001': { id: 'LG001', name: 'integrity-changed', severity: 'critical',
    help: 'Same package version but a different integrity hash. Published npm versions are immutable, so this usually means tampering, a registry swap, or a hand-edited lockfile.' },
  'LG002': { id: 'LG002', name: 'non-registry-source', severity: 'high',
    help: 'Package resolved from a git URL, tarball URL, or a host outside the allowed registries. These bypass registry provenance and can change without a version bump.' },
  'LG003': { id: 'LG003', name: 'insecure-protocol', severity: 'high',
    help: 'Package resolved over plain http:// or git://, which can be modified in transit.' },
  'LG004': { id: 'LG004', name: 'new-install-script', severity: 'high',
    help: 'A package that runs preinstall/install/postinstall scripts was added, or an existing package started running one. Install scripts are the main execution vector of npm worms such as Shai-Hulud.' },
  'LG005': { id: 'LG005', name: 'missing-integrity', severity: 'medium',
    help: 'Registry package with no integrity hash, so npm cannot verify the tarball.' },
  'LG006': { id: 'LG006', name: 'source-changed', severity: 'medium',
    help: 'Same name and version, but the resolved URL changed.' },
  'LG007': { id: 'LG007', name: 'version-downgrade', severity: 'low',
    help: 'A package moved to a lower version. Sometimes intended, sometimes used to reintroduce a vulnerable or malicious release.' },
  'LG008': { id: 'LG008', name: 'package-added', severity: 'info',
    help: 'A new package entered the dependency tree. Listed so reviewers can see the full blast radius of a lockfile change.' },
  'LG009': { id: 'LG009', name: 'name-mismatch', severity: 'high',
    help: 'The resolved tarball URL names a different package than the install path (a dependency-confusion / alias trick).' },
};

const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'];

function sevRank(s) { return SEVERITY_ORDER.indexOf(s); }

function cmpVersion(a, b) {
  const pa = String(a).split(/[.+-]/).slice(0, 3).map((x) => parseInt(x, 10) || 0);
  const pb = String(b).split(/[.+-]/).slice(0, 3).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < 3; i++) if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1;
  return 0;
}

function classifySource(resolved, registries) {
  if (!resolved) return { kind: 'none' };
  if (/^(git\+|git:|github:|gitlab:|bitbucket:)/.test(resolved)) return { kind: 'git', insecure: /^git:\/\//.test(resolved) || /^git\+http:/.test(resolved) };
  if (/^file:/.test(resolved)) return { kind: 'file' };
  if (/^https?:\/\//.test(resolved)) {
    const insecure = resolved.startsWith('http://');
    const norm = resolved.replace(/^http:/, 'https:');
    const onRegistry = registries.some((r) => norm.startsWith(r.replace(/^http:/, 'https:')));
    return { kind: onRegistry ? 'registry' : 'url', insecure };
  }
  return { kind: 'other' };
}

// Expected package name from a registry tarball URL: <reg>/<name>/-/<file>.tgz
function nameFromTarball(resolved) {
  const m = /^https?:\/\/[^/]+(\/[^?#]*)\/-\/[^/]+\.tgz/.exec(resolved || '');
  if (!m) return null;
  const segs = decodeURIComponent(m[1]).split('/').filter(Boolean);
  if (!segs.length) return null;
  const last = segs[segs.length - 1];
  if (last.startsWith('@') && last.includes('/')) return last; // %2f-encoded scope
  const prev = segs[segs.length - 2];
  return prev && prev.startsWith('@') ? `${prev}/${last}` : last;
}

module.exports = { RULES, SEVERITY_ORDER, sevRank, cmpVersion, classifySource, nameFromTarball, DEFAULT_REGISTRIES };
