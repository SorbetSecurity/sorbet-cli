/*
 * sorb Node require/import probe.
 *
 * Injected via NODE_OPTIONS="--require <this>". Wraps Module._resolveFilename
 * so every resolved module path is observed; paths inside node_modules are
 * mapped to their package name + version and appended to $SORB_TRACE_OUT as
 * NDJSON. No privileges needed.
 */
'use strict';

const outPath = process.env.SORB_TRACE_OUT;
if (outPath) {
  const Module = require('module');
  const fs = require('fs');
  const path = require('path');
  const seen = new Set();
  const orig = Module._resolveFilename;

  function packageOf(resolved) {
    const idx = resolved.lastIndexOf('node_modules' + path.sep);
    if (idx < 0) return null;
    let rest = resolved.slice(idx + ('node_modules' + path.sep).length);
    const parts = rest.split(path.sep);
    let name = parts[0];
    if (name.startsWith('@') && parts.length > 1) name = name + '/' + parts[1];
    const pkgDir = resolved.slice(0, idx) + 'node_modules' + path.sep + name;
    let version = '';
    try {
      version = JSON.parse(fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8')).version || '';
    } catch (e) { /* ignore */ }
    return { name, version };
  }

  Module._resolveFilename = function (request, parent, isMain, options) {
    const resolved = orig.call(this, request, parent, isMain, options);
    try {
      const pkg = packageOf(resolved);
      if (pkg && !seen.has(pkg.name)) {
        seen.add(pkg.name);
        fs.appendFileSync(outPath, JSON.stringify({
          technique: 'node-require-probe',
          kind: 'module',
          identifier: pkg.name,
          detail: pkg.version,
          ecosystem: 'npm',
        }) + '\n');
      }
    } catch (e) { /* never break the traced program */ }
    return resolved;
  };
}
