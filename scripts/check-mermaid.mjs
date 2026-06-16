#!/usr/bin/env node
// Validate every ```mermaid block in a markdown file against the real Mermaid
// parser (the same grammar GitHub / VS Code use to render).
//
// Usage:  npm i mermaid jsdom   &&   node scripts/check-mermaid.mjs ARCHITECTURE.md
// Exits non-zero and prints the offending block + parser error if any fail.

import { JSDOM } from 'jsdom';
import { readFileSync } from 'node:fs';

const path = process.argv[2];
if (!path) {
  console.error('usage: node scripts/check-mermaid.mjs <markdown-file>');
  process.exit(2);
}

const dom = new JSDOM('<!DOCTYPE html><body></body>', { url: 'http://localhost/' });
globalThis.window = dom.window;
globalThis.document = dom.window.document;
try { if (!globalThis.navigator) globalThis.navigator = dom.window.navigator; } catch {}

const { default: mermaid } = await import('mermaid');
mermaid.initialize({ startOnLoad: false, securityLevel: 'loose' });

const lines = readFileSync(path, 'utf8').split('\n');
const blocks = [];
let cur = null;
lines.forEach((line, i) => {
  if (cur === null && /^```mermaid\s*$/.test(line)) cur = { start: i + 1, text: [] };
  else if (cur !== null && /^```\s*$/.test(line)) { cur.end = i + 1; blocks.push(cur); cur = null; }
  else if (cur !== null) cur.text.push(line);
});

let fail = 0;
for (const b of blocks) {
  const first = (b.text.find((l) => l.trim()) || '').trim();
  try {
    await mermaid.parse(b.text.join('\n'));
    console.log(`OK    L${b.start}-${b.end}  ${first}`);
  } catch (e) {
    fail++;
    console.log(`FAIL  L${b.start}-${b.end}  ${first}`);
    console.log('      ' + String((e && e.message) || e).split('\n').slice(0, 8).join('\n      '));
  }
}
console.log(`\n${blocks.length} diagrams, ${fail} failed`);
process.exit(fail ? 1 : 0);
