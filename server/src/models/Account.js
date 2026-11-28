// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/models/Account.js
// Purpose : Data-access layer for account self-service. setPassword stores a
//           new bcrypt hash and records password_changed_at (the route has
//           already verified the old passphrase). countRecentEvents counts a
//           user's audit-log events of one kind in the last N minutes; the
//           account routes use it to lock the passphrase checks after repeated
//           failures. exportData gathers EVERYTHING the server holds about one
//           user for a data-portability download: profile, settings, contacts,
//           blocks, signed-in devices, security events, groups, the most
//           recent 2000 direct and 2000 group messages (ciphertext only - the
//           server cannot read them - with their edit times), reactions the
//           user gave, two-factor status (never the secret or the codes), the
//           number of messages the user pinned, reports they filed, file
//           metadata, pending scheduled-message count and chat preferences. It
//           never returns password hashes, other people's data beyond
//           usernames, or anything unreadable by design. checkupFacts runs one
//           query that returns the raw numbers the security checkup is based
//           on (active devices, recent failed logins and key changes, passphrase
//           age, groups waiting for a new key, whether two-factor is on). All
//           queries are parameterised.
// =============================================================================
import { query } from '../config/db.js';

export async function setPassword(userId, passwordHash) {
  await query(
    'UPDATE users SET password_hash = $2, password_changed_at = now(), updated_at = now() WHERE id = $1',
    [userId, passwordHash]
  );
}

export async function countRecentEvents(userId, event, minutes) {
  const { rows } = await query(
    `SELECT count(*)::int AS n FROM auth_events
     WHERE user_id = $1 AND event = $2 AND created_at > now() - make_interval(mins => $3::int)`,
    [userId, event, minutes]
  );
  return rows[0].n;
}

export async function exportData(userId) {
  const [
    profile, settings, contacts, blocks, sessions, events, groups, direct, group,
    reports, files, scheduled, prefs, reactions, twoFactor, pins,
  ] = await Promise.all([
    query('SELECT username, created_at, password_changed_at, public_key FROM users WHERE id = $1', [userId]),
    query('SELECT show_presence, show_typing, read_receipts, status FROM user_settings WHERE user_id = $1', [userId]),
    query(
      `SELECT u.username, c.created_at FROM contacts c JOIN users u ON u.id = c.contact_id
       WHERE c.owner_id = $1 ORDER BY u.username`,
      [userId]
    ),
    query(
      `SELECT u.username, b.created_at FROM blocks b JOIN users u ON u.id = b.blocked_id
       WHERE b.blocker_id = $1 ORDER BY u.username`,
      [userId]
    ),
    query(
      `SELECT device_label, created_at, last_seen_at, expires_at FROM sessions
       WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now() ORDER BY last_seen_at DESC`,
      [userId]
    ),
    query(
      'SELECT event, device_label, created_at FROM auth_events WHERE user_id = $1 ORDER BY created_at DESC LIMIT 500',
      [userId]
    ),
    query(
      `SELECT g.name, gm.role, gm.joined_at, g.epoch FROM group_members gm JOIN chat_groups g ON g.id = gm.group_id
       WHERE gm.user_id = $1 ORDER BY g.name`,
      [userId]
    ),
    query(
      `SELECT m.id, fu.username AS from_username, tu.username AS to_username, m.ciphertext, m.iv,
              m.created_at, m.expires_at, m.edited_at
       FROM messages m JOIN users fu ON fu.id = m.from_id JOIN users tu ON tu.id = m.to_id
       WHERE (m.from_id = $1 OR m.to_id = $1) AND (m.expires_at IS NULL OR m.expires_at > now())
       ORDER BY m.created_at DESC LIMIT 2000`,
      [userId]
    ),
    query(
      `SELECT m.id, g.name AS group_name, u.username AS from_username, m.epoch, m.ciphertext, m.iv,
              m.created_at, m.expires_at, m.edited_at
       FROM group_messages m
       JOIN group_members gm ON gm.group_id = m.group_id AND gm.user_id = $1
       JOIN chat_groups g ON g.id = m.group_id
       JOIN users u ON u.id = m.from_id
       WHERE m.created_at >= gm.joined_at AND (m.expires_at IS NULL OR m.expires_at > now())
       ORDER BY m.created_at DESC LIMIT 2000`,
      [userId]
    ),
    query('SELECT target_type, reason, status, created_at FROM reports WHERE reporter_id = $1 ORDER BY created_at DESC', [userId]),
    query(
      `SELECT id, kind, size_bytes::float8 AS size_bytes, status, created_at, expires_at
       FROM files WHERE owner_id = $1 AND expires_at > now() ORDER BY created_at DESC`,
      [userId]
    ),
    query('SELECT count(*)::int AS n FROM scheduled_messages WHERE from_id = $1', [userId]),
    query(
      `SELECT u.username AS peer_username, g.name AS group_name, p.pinned, p.archived, p.muted_until, p.default_ttl_seconds
       FROM chat_prefs p LEFT JOIN users u ON u.id = p.peer_id LEFT JOIN chat_groups g ON g.id = p.group_id
       WHERE p.user_id = $1`,
      [userId]
    ),
    query(
      `SELECT kind, reaction, created_at FROM (
         SELECT 'direct'::text AS kind, reaction, created_at FROM direct_reactions WHERE user_id = $1
         UNION ALL
         SELECT 'group'::text AS kind, reaction, created_at FROM group_reactions WHERE user_id = $1
       ) r ORDER BY created_at DESC LIMIT 1000`,
      [userId]
    ),
    query(
      `SELECT COALESCE((SELECT enabled FROM two_factor WHERE user_id = $1), false) AS enabled,
              (SELECT enabled_at FROM two_factor WHERE user_id = $1) AS enabled_at,
              (SELECT count(*)::int FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL) AS recovery_codes_remaining`,
      [userId]
    ),
    query(
      `SELECT ((SELECT count(*) FROM pinned_direct WHERE pinned_by = $1)
             + (SELECT count(*) FROM pinned_group WHERE pinned_by = $1))::int AS n`,
      [userId]
    ),
  ]);

  return {
    profile: profile.rows[0],
    settings: settings.rows[0] ?? { show_presence: true, show_typing: true, read_receipts: true, status: 'available' },
    twoFactor: twoFactor.rows[0],
    contacts: contacts.rows,
    blocks: blocks.rows,
    sessions: sessions.rows,
    securityEvents: events.rows,
    groups: groups.rows,
    directMessages: direct.rows,
    groupMessages: group.rows,
    reactionsGiven: reactions.rows,
    pinsCreated: pins.rows[0].n,
    reportsFiled: reports.rows,
    files: files.rows,
    scheduledMessagesPending: scheduled.rows[0].n,
    chatPreferences: prefs.rows,
  };
}

export async function checkupFacts(userId) {
  const { rows } = await query(
    `SELECT
       (SELECT count(*)::int FROM sessions WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()) AS active_sessions,
       (SELECT count(*)::int FROM auth_events WHERE user_id = $1 AND event = 'login_failed'
          AND created_at > now() - interval '7 days') AS failed_logins,
       (SELECT count(*)::int FROM auth_events WHERE user_id = $1 AND event = 'key_rotated'
          AND created_at > now() - interval '7 days') AS key_changes,
       (SELECT (EXTRACT(EPOCH FROM (now() - password_changed_at)) / 86400)::float8 FROM users WHERE id = $1) AS password_age_days,
       (SELECT count(*)::int FROM group_members gm JOIN chat_groups g ON g.id = gm.group_id
          WHERE gm.user_id = $1 AND gm.role = 'admin' AND g.needs_rekey) AS rekey_pending,
       COALESCE((SELECT enabled FROM two_factor WHERE user_id = $1), false) AS two_factor_enabled`,
    [userId]
  );
  return rows[0];
}

// File: server/src/models/Account.js
// End of file