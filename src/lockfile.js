'use strict';
// Parse npm package-lock.json (lockfileVersion 1, 2, 3) into a flat map of
// "install path" -> { name, version, resolved, integrity, hasInstallScript, dev, optional }.

function nameFromPath(p) {
  const i = p.lastIndexOf('node_modules/');
  return i === -1 ? p : p.slice(i + 'node_modules/'.length);
}

function fromV2(lock) {
  const out = new Map();
  for (const [path, meta] of Object.entries(lock.packages || {})) {
    if (path === '' || !meta) continue; // root project
    if (meta.link) continue; // workspace symlink
    out.set(path, {
      path,
      name: meta.name || nameFromPath(path),
      version: meta.version || null,
      resolved: meta.resolved || null,
      integrity: meta.integrity || null,
      hasInstallScript: Boolean(meta.hasInstallScript),
      dev: Boolean(meta.dev),
      optional: Boolean(meta.optional),
    });
  }
  return out;
}

function fromV1(lock) {
  const out = new Map();
  const walk = (deps, prefix) => {
    for (const [name, meta] of Object.entries(deps || {})) {
      const path = `${prefix}node_modules/${name}`;
      out.set(path, {
        path,
        name,
        version: meta.version || null,
        resolved: meta.resolved || null,
        integrity: meta.integrity || null,
        hasInstallScript: false, // v1 lockfiles do not record this
        dev: Boolean(meta.dev),
        optional: Boolean(meta.optional),
      });
      if (meta.dependencies) walk(meta.dependencies, `${path}/`);
    }
  };
  walk(lock.dependencies, '');
  return out;
}

function parseLockfile(text, label = 'lockfile') {
  let lock;
  try {
    lock = JSON.parse(text);
  } catch (e) {
    throw new Error(`${label}: not valid JSON (${e.message})`);
  }
  if (!lock || typeof lock !== 'object') throw new Error(`${label}: not a package-lock object`);
  const v = lock.lockfileVersion || 1;
  const packages = lock.packages ? fromV2(lock) : fromV1(lock);
  return { lockfileVersion: v, packages };
}

module.exports = { parseLockfile, nameFromPath };
