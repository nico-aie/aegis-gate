#!/usr/bin/env node
// Rules-of-hooks guard for the hand-bundled dashboard.
//
// eslint-plugin-react-hooks does NOT work here: this codebase calls
// cross-file hooks as `window.useX()`, and rules-of-hooks only recognizes
// bare `useX()` / `React.useX()` — so it is blind to the dominant pattern
// (it reported 0 errors on the real #310 bug). This AST check is tuned to
// the codebase and catches the two ways hooks have actually broken it:
//
//   1. BARE-HOOK-IN-ALIASED-MODULE — a React built-in hook (useEffect, …)
//      CALLED bare in a module that renamed it (widgets.jsx -> *W,
//      pages.jsx -> *P). The bare name is undefined at runtime → blank
//      console. (esbuild only transforms JSX; it never resolves idents.)
//
//   2. HOOK-AFTER-EARLY-RETURN (React #310) — a hook call (bare `useX()`
//      OR `window.useX()` OR `React.useX()`) that appears at the top level
//      of a component/hook function AFTER a top-level `return`. On renders
//      where the early return fires, the hook is skipped; when it doesn't,
//      the hook runs → "rendered more hooks than the previous render".
//
// The pervasive existence-guard ternary (`window.useX ? window.useX() : d`)
// is intentionally NOT flagged on its own — only when it sits after an
// early return (which is the actual violation).

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Parser } from 'acorn';
import jsx from 'acorn-jsx';

const JsxParser = Parser.extend(jsx());
const HERE = dirname(fileURLToPath(import.meta.url));
const FILES = ['src/widgets.jsx', 'src/data.jsx', 'src/pages.jsx', 'src/help.jsx', 'src/app.jsx'];
const HOOK_RE = /^use[A-Z0-9]/;
const REACT_HOOKS = new Set([
  'useState', 'useEffect', 'useRef', 'useMemo', 'useCallback',
  'useReducer', 'useContext', 'useLayoutEffect', 'useSyncExternalStore',
]);

let failures = 0;
const fail = (file, node, msg) => {
  const line = node.loc ? node.loc.start.line : '?';
  console.error(`[lint-hooks] ${file}:${line} — ${msg}`);
  failures++;
};

// The hook-name of a CallExpression callee, or null if it isn't a hook call.
// Recognizes `useX()`, `window.useX()`, `React.useX()`, `x.useX()`.
function calleeHookName(callee) {
  if (callee.type === 'Identifier' && HOOK_RE.test(callee.name)) return callee.name;
  if (callee.type === 'MemberExpression' && !callee.computed &&
      callee.property.type === 'Identifier' && HOOK_RE.test(callee.property.name)) {
    return callee.property.name;
  }
  return null;
}

// Collect top-level hook CALLs within a statement subtree, WITHOUT
// descending into nested functions (their hooks belong to their own scope).
function collectTopLevelHookCalls(node, out) {
  if (!node || typeof node.type !== 'string') return;
  if (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' ||
      node.type === 'ArrowFunctionExpression') {
    return; // don't descend into inner functions/callbacks
  }
  if (node.type === 'CallExpression') {
    const name = calleeHookName(node.callee);
    if (name) out.push({ node, name });
  }
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'start' || key === 'end') continue;
    const v = node[key];
    if (Array.isArray(v)) v.forEach((c) => c && collectTopLevelHookCalls(c, out));
    else if (v && typeof v.type === 'string') collectTopLevelHookCalls(v, out);
  }
}

// Does a top-level statement early-return? (`return …` or `if (…) return …`)
function isEarlyReturn(stmt) {
  if (stmt.type === 'ReturnStatement') return true;
  if (stmt.type === 'IfStatement') {
    const bodies = [stmt.consequent, stmt.alternate].filter(Boolean);
    return bodies.some((b) =>
      b.type === 'ReturnStatement' ||
      (b.type === 'BlockStatement' && b.body.some((s) => s.type === 'ReturnStatement')));
  }
  return false;
}

// Walk a component/hook function body: flag any top-level hook call that
// appears after a top-level early return.
function checkFunctionBody(file, body) {
  let returnSeen = false;
  for (const stmt of body) {
    if (returnSeen) {
      const hooks = [];
      collectTopLevelHookCalls(stmt, hooks);
      for (const h of hooks) {
        fail(file, h.node,
          `hook \`${h.name}()\` called after an early return — the hook ` +
          `count varies between renders (React #310). Move it above the return.`);
      }
    }
    if (isEarlyReturn(stmt)) returnSeen = true;
  }
}

// Is this a component (PascalCase) or custom-hook (use…) function?
const isComponentOrHook = (name) => !!name && (/^[A-Z]/.test(name) || HOOK_RE.test(name));

function walkForFunctions(file, node, visit) {
  if (!node || typeof node.type !== 'string') return;
  if (node.type === 'FunctionDeclaration' && node.id) visit(node.id.name, node.body);
  if (node.type === 'VariableDeclarator' && node.id?.type === 'Identifier' && node.init &&
      (node.init.type === 'ArrowFunctionExpression' || node.init.type === 'FunctionExpression') &&
      node.init.body?.type === 'BlockStatement') {
    visit(node.id.name, node.init.body);
  }
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'start' || key === 'end') continue;
    const v = node[key];
    if (Array.isArray(v)) v.forEach((c) => c && walkForFunctions(file, c, visit));
    else if (v && typeof v.type === 'string') walkForFunctions(file, v, visit);
  }
}

// --- bug #1: bare React hook in a module that renamed it ---
function checkBareAliasedHooks(file, src) {
  const localBindings = new Set();
  for (const m of src.matchAll(/const\s*\{([^}]*)\}\s*=\s*React\b/g)) {
    for (const raw of m[1].split(',')) {
      const [name, alias] = raw.trim().split(':').map((s) => s.trim());
      if (name) localBindings.add(alias || name);
    }
  }
  for (const hook of REACT_HOOKS) {
    if (localBindings.has(hook)) continue;
    const callRe = new RegExp(`(?<![.\\w])${hook}\\s*\\(`, 'g');
    for (const m of src.matchAll(callRe)) {
      const line = src.slice(0, m.index).split('\n').length;
      console.error(
        `[lint-hooks] ${file}:${line} — bare \`${hook}(\` but this module ` +
        `does not destructure \`${hook}\` (renamed alias in use). Use the alias.`);
      failures++;
    }
  }
}

for (const rel of FILES) {
  let src;
  try { src = readFileSync(join(HERE, rel), 'utf8'); } catch { continue; }

  checkBareAliasedHooks(rel, src);

  let ast;
  try {
    ast = JsxParser.parse(src, { ecmaVersion: 'latest', sourceType: 'script', locations: true });
  } catch (e) {
    console.error(`[lint-hooks] ${rel}: parse error — ${e.message}`);
    failures++;
    continue;
  }
  walkForFunctions(rel, ast, (name, body) => {
    if (isComponentOrHook(name)) checkFunctionBody(rel, body.body);
  });
}

if (failures > 0) {
  console.error(`\n[lint-hooks] FAILED: ${failures} rules-of-hooks violation(s).`);
  process.exit(1);
}
console.log('[lint-hooks] ok — no bare-hook or hook-after-return violations.');
