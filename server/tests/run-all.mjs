// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/tests/run-all.mjs
// Purpose : Runs every automated test suite one after another and prints a
//           final summary. Suites: day3b (burn-on-read and self-destruct
//           rooms, about 50 s), day4 (settings, presence, typing, read
//           receipts, encrypted files, about 45 s) and day5 (hardening, reports
//           and moderation, about 15 s). Each suite is a separate process whose
//           output is shown live; the runner exits with code 1 if any suite
//           failed, so it can also gate a CI pipeline. The server must be
//           running, started with TEST_MODE=1 so that rate limits do not stop
//           repeated runs (PowerShell: $env:TEST_MODE='1'; npm run dev).
//           Run it with:  npm test
//           The PowerShell suite day3a.ps1 (invite links) is separate:
//           powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\day3a.ps1
// =============================================================================
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.dirname(fileURLToPath(import.meta.url));
const suites = ['day3b.mjs', 'day4.mjs', 'day5.mjs'];
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