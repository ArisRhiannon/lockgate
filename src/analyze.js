'use strict';
const { RULES, sevRank, cmpVersion, classifySource, nameFromTarball, DEFAULT_REGISTRIES } = require('./rules');

function finding(ruleId, pkg, message, extra = {}) {
  const r = RULES[ruleId];
  return { ruleId, rule: r.name, severity: r.severity, package: pkg.name, version: pkg.version, path: pkg.path, message, ...extra };
}

function checkEntry(pkg, registries, out) {
  const src = classifySource(pkg.resolved, registries);
  if (src.insecure) out.push(finding('LG003', pkg, `${pkg.name}@${pkg.version} resolved over an insecure protocol: ${pkg.resolved}`));
  if (src.kind === 'git' || src.kind === 'url' || src.kind === 'other') {
    out.push(finding('LG002', pkg, `${pkg.name}@${pkg.version} resolved from a non-registry source: ${pkg.resolved}`));
  }
  if (src.kind === 'registry') {
    if (!pkg.integrity) out.push(finding('LG005', pkg, `${pkg.name}@${pkg.version} has no integrity hash`));
    const tarName = nameFromTarball(pkg.resolved);
    if (tarName && tarName !== pkg.name) {
      out.push(finding('LG009', pkg, `install path says "${pkg.name}" but tarball is "${tarName}" (${pkg.resolved})`));
    }
  }
}

/**
 * Compare two parsed lockfiles. If `base` is null, audit `head` on its own
 * (every package is treated as "present" but not "added").
 */
function analyze(base, head, opts = {}) {
  const registries = (opts.registries && opts.registries.length ? opts.registries : DEFAULT_REGISTRIES)
    .map((r) => (r.endsWith('/') ? r : `${r}/`));
  const findings = [];
  const stats = { added: 0, removed: 0, changed: 0, unchanged: 0, total: head.packages.size };

  for (const [path, pkg] of head.packages) {
    const prev = base ? base.packages.get(path) : undefined;
    if (base && !prev) {
      stats.added++;
      findings.push(finding('LG008', pkg, `added ${pkg.name}@${pkg.version}`));
      if (pkg.hasInstallScript) findings.push(finding('LG004', pkg, `new package ${pkg.name}@${pkg.version} runs an install script`));
      checkEntry(pkg, registries, findings);
      continue;
    }
    if (!base) {
      checkEntry(pkg, registries, findings);
      if (pkg.hasInstallScript && opts.listInstallScripts) findings.push(finding('LG004', pkg, `${pkg.name}@${pkg.version} runs an install script`));
      continue;
    }
    const same = prev.version === pkg.version && prev.resolved === pkg.resolved && prev.integrity === pkg.integrity && prev.hasInstallScript === pkg.hasInstallScript;
    if (same) { stats.unchanged++; continue; }
    stats.changed++;
    if (prev.version === pkg.version) {
      if (prev.integrity && pkg.integrity && prev.integrity !== pkg.integrity) {
        findings.push(finding('LG001', pkg, `${pkg.name}@${pkg.version} integrity changed from ${prev.integrity.slice(0, 20)}… to ${pkg.integrity.slice(0, 20)}…`, { before: prev.integrity, after: pkg.integrity }));
      }
      if (prev.resolved && pkg.resolved && prev.resolved !== pkg.resolved) {
        findings.push(finding('LG006', pkg, `${pkg.name}@${pkg.version} source changed: ${prev.resolved} -> ${pkg.resolved}`, { before: prev.resolved, after: pkg.resolved }));
      }
    } else if (prev.version && pkg.version && cmpVersion(pkg.version, prev.version) < 0) {
      findings.push(finding('LG007', pkg, `${pkg.name} downgraded ${prev.version} -> ${pkg.version}`, { before: prev.version, after: pkg.version }));
    }
    if (!prev.hasInstallScript && pkg.hasInstallScript) {
      findings.push(finding('LG004', pkg, `${pkg.name} now runs an install script (${prev.version} -> ${pkg.version})`));
    }
    // Only re-check source properties that actually changed, to keep diffs quiet.
    if (prev.resolved !== pkg.resolved || prev.integrity !== pkg.integrity) checkEntry(pkg, registries, findings);
  }
  if (base) for (const path of base.packages.keys()) if (!head.packages.has(path)) stats.removed++;

  const ignore = new Set(opts.ignore || []);
  const kept = findings.filter((f) => !ignore.has(f.ruleId) && !ignore.has(f.rule) && !ignore.has(f.package));
  kept.sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || a.path.localeCompare(b.path));
  return { findings: kept, stats };
}

module.exports = { analyze };
