// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/utils/loadRoutes.js
// Purpose : Automatically mounts every router in server/src/routes, so adding
//           an API feature means adding ONE file and never editing server.js.
//           Convention: routes/<name>.js (default export: an Express Router) is
//           mounted at /api/<name>. Two exceptions are declared below:
//           'invites' is mounted at /api (its paths already start with /groups
//           or /invites) and is loaded FIRST so authentication runs only once
//           per request on those paths. Files that do not export a router are
//           skipped. Each mount is logged at startup so you can see exactly
//           what is live.
// =============================================================================
import { readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROUTES_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'routes');
const MOUNT_OVERRIDES = { invites: '/api' };
const LOAD_FIRST = ['invites'];

export async function mountRoutes(app) {
  const names = readdirSync(ROUTES_DIR)
    .filter((f) => /^[a-z][a-z0-9-]*\.js$/i.test(f))
    .map((f) => f.slice(0, -3))
    .sort((a, b) => Number(LOAD_FIRST.includes(b)) - Number(LOAD_FIRST.includes(a)) || a.localeCompare(b));

  for (const name of names) {
    const mod = await import(pathToFileURL(path.join(ROUTES_DIR, `${name}.js`)).href);
    if (typeof mod.default !== 'function') continue;
    const mountAt = MOUNT_OVERRIDES[name] ?? `/api/${name}`;
    app.use(mountAt, mod.default);
    console.log(`[routes] ${mountAt}  <-  ${name}.js`);
  }
}

// File: server/src/utils/loadRoutes.js
// End of file