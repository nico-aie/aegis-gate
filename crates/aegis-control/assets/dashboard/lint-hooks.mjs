#!/usr/bin/env node
// Guard against the "bare hook in an aliased module" bug class.
//
// Each dashboard source destructures the React hooks it needs, and some
// modules RENAME them to avoid cross-IIFE collisions in the concatenated
// bundle (widgets.jsx -> *W, pages.jsx -> *P). If such a module then
// calls the BARE name (`useEffect(...)` instead of `useEffectW(...)`),
// the identifier is undefined at runtime and the component throws a
// ReferenceError on render — blanking the whole console. esbuild only
// transforms JSX (it does not resolve identifiers), so the bundle builds
// clean while being broken. This static check catches it at build time.
//
// Rule: for each file, a React built-in hook name may be *called* bare
// ONLY if that file destructures it under its own (unrenamed) name.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const FILES = [
  'src/widgets.jsx',
  'src/data.jsx',
  'src/pages.jsx',
  'src/help.jsx',
  'src/app.jsx',
];

const HOOKS = [
  'useState', 'useEffect', 'useRef', 'useMemo', 'useCallback',
  'useReducer', 'useContext', 'useLayoutEffect', 'useSyncExternalStore',
];

let failures = 0;

for (const rel of FILES) {
  const path = join(HERE, rel);
  let src;
  try {
    src = readFileSync(path, 'utf8');
  } catch {
    continue; // optional file
  }

  // Collect the local bindings from every `const { ... } = React;`.
  // An entry is `name` (bare) or `name: alias` (renamed local binding).
  const localBindings = new Set();
  for (const m of src.matchAll(/const\s*\{([^}]*)\}\s*=\s*React\b/g)) {
    for (const raw of m[1].split(',')) {
      const part = raw.trim();
      if (!part) continue;
      const [name, alias] = part.split(':').map((s) => s.trim());
      localBindings.add(alias || name); // the in-scope identifier
    }
  }

  for (const hook of HOOKS) {
    if (localBindings.has(hook)) continue; // legitimately bare here
    // A CALL of the bare hook, not qualified (`React.`/`window.`) and not
    // part of a longer identifier (`useEffectW`). Requires a `(` so prose
    // / comments that merely mention the hook don't false-positive.
    const callRe = new RegExp(`(?<![.\\w])${hook}\\s*\\(`, 'g');
    for (const m of src.matchAll(callRe)) {
      const line = src.slice(0, m.index).split('\n').length;
      console.error(
        `[lint-hooks] ${rel}:${line} — bare \`${hook}(\` but this module ` +
          `does not destructure \`${hook}\` (renamed alias in use). ` +
          `Use the module's alias.`,
      );
      failures++;
    }
  }
}

if (failures > 0) {
  console.error(`\n[lint-hooks] FAILED: ${failures} bare-hook reference(s).`);
  process.exit(1);
}
console.log('[lint-hooks] ok — no bare hook references in aliased modules.');
