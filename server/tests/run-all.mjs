// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/tests/run-all.mjs
// Purpose : Runs every automated test suite one after another and prints a
//           final summary. Suites are DISCOVERED automatically: any file in the
//           tests folder named day<number>[letter].mjs (day3b.mjs, day4.mjs,
//           day5.mjs, day6.mjs ...) is run in alphabetical order, so adding a
//           new suite never requires editing this file. Each suite is a
//           separate process whose output is shown live; the runner exits with
//           code 1 if any suite failed, so it can also gate a CI pipeline.
//           The server must be running in ANOTHER terminal, started with
//           TEST_MODE=1 so rate limits do not stop repeated runs (PowerShell:
//           $env:TEST_MODE='1'; npm run dev). Run it with:  npm test
//           The PowerShell suite day3a.ps1 (invite links) is separate:
//           powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\day3a.ps1
//           If the server is not reachable the runner says so immediately
//           instead of letting every suite crash with a network error.
// =============================================================================
import { spawn } from 'node:child_process';
import { readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.dirname(fileURLToPath(import.meta.url));
const suites = readdirSync(dir)
  .filter((f) => /^day\d+[a-z]?\.mjs$/.test(f))
  .sort();

try {
  const res = await fetch('http://localhost:5000/api/ready');
  if (!res.ok) throw new Error(`status ${res.status}`);
} catch {
  console.error('\nThe server is not reachable on http://localhost:5000.');
  console.error('Start it in ANOTHER terminal first:');
  console.error("  cd server; $env:TEST_MODE = '1'; npm run dev\n");
  process.exit(1);
}

const results = [];
for (const suite of suites) {
  console.log(`\n=================== ${suite} ===================`);
  const code = await new Promise((resolve) => {
    const child = spawn(process.execPath, [path.join(dir, suite)], { stdio: 'inherit' });
    child.on('exit', (c) => resolve(c ?? 1));
    child.on('error', () => resolve(1));
  });
  results.push({ suite, ok: code === 0 });
}

console.log('\n=================== SUMMARY ===================');
for (const r of results) {
  console.log(`${r.ok ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m'}  ${r.suite}`);
}
process.exit(results.every((r) => r.ok) ? 0 : 1);

// File: server/tests/run-all.mjs
// End of file