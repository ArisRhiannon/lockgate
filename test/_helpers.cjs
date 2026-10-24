'use strict';
const reg = (n, v) => `https://registry.npmjs.org/${n}/-/${n.split('/').pop()}-${v}.tgz`;
function lock(pkgs) {
  const packages = { '': { name: 'app', version: '1.0.0' } };
  for (const [name, meta] of Object.entries(pkgs)) {
    packages[`node_modules/${name}`] = { version: meta.version, resolved: meta.resolved ?? reg(name, meta.version), integrity: meta.integrity === undefined ? `sha512-${name}-${meta.version}` : meta.integrity, ...(meta.extra || {}) };
  }
  return JSON.stringify({ name: 'app', lockfileVersion: 3, requires: true, packages });
}
module.exports = { lock, reg };
