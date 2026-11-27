// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/utils/storage.js
// Purpose : The only place that touches the disk for uploaded files. Encrypted
//           attachments are stored as opaque blobs named after their UUID in
//           <UPLOAD_DIR>/blobs (default: server/storage), with in-progress
//           uploads in <UPLOAD_DIR>/parts and renamed into blobs/ only once
//           complete, so a half-written file can never be served.
//           Safety: every path is built from an id that must pass the UUID
//           check, so path traversal ("../") is impossible; directories and
//           files are created with owner-only permissions. Exposes: ensureStorage
//           (create directories), blobPath/partPath, removeBlob (deletes both
//           copies, ignoring "not found"), and listStored (used by the file
//           sweeper to find orphaned blobs). To move storage to S3 or another
//           disk later, only this file and the file routes need to change.
// =============================================================================
import { mkdir, unlink, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import '../config/env.js'; // loads .env so UPLOAD_DIR is available
import { isUuid } from './serialize.js';

const SERVER_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const ROOT = path.resolve(process.env.UPLOAD_DIR || path.join(SERVER_ROOT, 'storage'));
const BLOBS = path.join(ROOT, 'blobs');
const PARTS = path.join(ROOT, 'parts');

function safeId(id) {
  if (!isUuid(id)) throw new Error('invalid file id');
  return id.toLowerCase();
}

export async function ensureStorage() {
  await mkdir(BLOBS, { recursive: true, mode: 0o700 });
  await mkdir(PARTS, { recursive: true, mode: 0o700 });
}

export const blobPath = (id) => path.join(BLOBS, safeId(id));
export const partPath = (id) => path.join(PARTS, safeId(id));

export async function removeBlob(id) {
  for (const p of [blobPath(id), partPath(id)]) {
    try {
      await unlink(p);
    } catch (err) {
      if (err.code !== 'ENOENT') console.error('[storage] could not delete', path.basename(p), err.code);
    }
  }
}

// Returns [{ id, kind: 'blob' | 'part', mtimeMs }] for every stored file.
export async function listStored() {
  const out = [];
  for (const [dir, kind] of [[BLOBS, 'blob'], [PARTS, 'part']]) {
    let names = [];
    try {
      names = await readdir(dir);
    } catch {
      continue;
    }
    for (const name of names) {
      if (!isUuid(name)) continue;
      try {
        const s = await stat(path.join(dir, name));
        out.push({ id: name.toLowerCase(), kind, mtimeMs: s.mtimeMs });
      } catch {
        /* file vanished while listing */
      }
    }
  }
  return out;
}

// File: server/src/utils/storage.js
// End of file