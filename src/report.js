'use strict';
const { RULES } = require('./rules');
const pkgJson = require('../package.json');

const SARIF_LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };

function toText(result, { color = false, minSeverity = 'info' } = {}) {
  const c = (code, s) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const colors = { critical: '1;31', high: '31', medium: '33', low: '36', info: '2' };
  const { findings, stats } = result;
  const lines = [];
  for (const f of findings) lines.push(`${c(colors[f.severity], f.severity.toUpperCase().padEnd(8))} ${f.ruleId} ${f.message}`);
  lines.push('');
  lines.push(`lockgate: ${stats.total} packages | +${stats.added} added, -${stats.removed} removed, ~${stats.changed} changed`);
  const counts = {};
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  lines.push(`findings: ${Object.entries(counts).map(([k, v]) => `${v} ${k}`).join(', ') || 'none'}`);
  return lines.join('\n');
}

function toJSON(result) {
  return JSON.stringify({ tool: 'lockgate', version: pkgJson.version, ...result }, null, 2);
}

function toSARIF(result, lockfileUri = 'package-lock.json') {
  const used = [...new Set(result.findings.map((f) => f.ruleId))];
  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: {
        name: 'lockgate', version: pkgJson.version, informationUri: pkgJson.homepage,
        rules: used.map((id) => ({ id, name: RULES[id].name, shortDescription: { text: RULES[id].name }, fullDescription: { text: RULES[id].help }, defaultConfiguration: { level: SARIF_LEVEL[RULES[id].severity] } })),
      } },
      results: result.findings.map((f) => ({
        ruleId: f.ruleId, level: SARIF_LEVEL[f.severity], message: { text: f.message },
        locations: [{ physicalLocation: { artifactLocation: { uri: lockfileUri } }, logicalLocations: [{ name: f.path, kind: 'package' }] }],
        properties: { severity: f.severity, package: f.package, version: f.version },
      })),
    }],
  }, null, 2);
}

module.exports = { toText, toJSON, toSARIF };
