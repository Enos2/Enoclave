// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/jobs/fileSweeper.js
// Purpose : Background job, started automatically at boot, that keeps the
//           encrypted-file store clean. Every minute it deletes the database
//           rows of expired files and of uploads that stayed unfinished for 30
//           minutes, and removes their bytes from disk. Every 10 minutes it
//           also reconciles the disk with the database: any stored blob or
//           temp file older than 10 minutes with NO matching row is an orphan
//           (left behind when a group was destroyed, an account was deleted, a
//           disk delete failed, or the server crashed mid-upload) and is
//           deleted. The database is the source of truth. A guard flag stops a
//           slow run from overlapping the next, errors are caught and logged,
//           and the timer is unref'd so it does not block shutdown.
// =============================================================================
import { sweepFiles, existingIds } from '../models/Attachment.js';
import { ensureStorage, listStored, removeBlob } from '../utils/storage.js';

const ORPHAN_MIN_AGE_MS = 10 * 60_000;
const RECONCILE_EVERY_MS = 10 * 60_000;

async function reconcile() {
  const old = (await listStored()).filter((s) => Date.now() - s.mtimeMs > ORPHAN_MIN_AGE_MS);
  for (let i = 0; i < old.length; i += 500) {
    const batch = old.slice(i, i + 500);
    const known = new Set(await existingIds(batch.map((b) => b.id)));
    for (const item of batch) if (!known.has(item.id)) await removeBlob(item.id);
  }
}

export function startFileSweeper() {
  let running = false;
  let lastReconcile = 0;

  const run = async () => {
    if (running) return;
    running = true;
    try {
      await ensureStorage();
      for (const id of await sweepFiles()) await removeBlob(id);
      if (Date.now() - lastReconcile > RECONCILE_EVERY_MS) {
        lastReconcile = Date.now();
        await reconcile();
      }
    } catch (err) {
      console.error('[jobs] file sweep failed:', err.message);
    } finally {
      running = false;
    }
  };

  run();
  const timer = setInterval(run, 60_000);
  timer.unref();
  return timer;
}

// File: server/src/jobs/fileSweeper.js
// End of file