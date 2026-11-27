// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/utils/loadJobs.js
// Purpose : Automatically starts every background job in server/src/jobs, so
//           adding a scheduled task means adding ONE file and never editing
//           server.js. Convention: any exported function whose name begins with
//           "start" (for example startRoomSweeper) is called once at boot with
//           { io }, the realtime server, so jobs can notify connected users.
//           Jobs are responsible for their own timers (use timer.unref() so a
//           job never keeps the process alive during shutdown) and for catching
//           their own errors.
// =============================================================================
import { readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const JOBS_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'jobs');

export async function startJobs(context) {
  const files = readdirSync(JOBS_DIR)
    .filter((f) => /^[a-zA-Z0-9_-]+\.js$/.test(f))
    .sort();
  for (const file of files) {
    const mod = await import(pathToFileURL(path.join(JOBS_DIR, file)).href);
    for (const [name, fn] of Object.entries(mod)) {
      if (name.startsWith('start') && typeof fn === 'function') {
        fn(context);
        console.log(`[jobs] started ${name}`);
      }
    }
  }
}

// File: server/src/utils/loadJobs.js
// End of file