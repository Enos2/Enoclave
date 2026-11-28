// =============================================================================
// Project : Enoclave - private, end-to-end encrypted web chat
// File    : server/src/utils/device.js
// Purpose : Privacy-preserving client information for the device list and
//           security log. hashIp turns a network address into a keyed
//           HMAC-SHA256 hash (key derived from JWT_SECRET), so the same
//           network can be recognised for lockouts WITHOUT the real address
//           ever being stored. deviceLabel reduces a User-Agent string to a
//           short label such as "Chrome on Windows". clientInfo(req) returns
//           both for a request. Raw IP addresses and full User-Agents are
//           never written to the database or the logs.
// =============================================================================
import crypto from 'node:crypto';
import { env } from '../config/env.js';

const IP_KEY = crypto.createHash('sha256').update(`enoclave-ip-hash:${env.jwtSecret}`).digest();

export function hashIp(ip) {
  return crypto.createHmac('sha256', IP_KEY).update(String(ip || '')).digest('hex').slice(0, 32);
}

export function deviceLabel(userAgent) {
  const ua = typeof userAgent === 'string' ? userAgent.slice(0, 300) : '';
  let browser = 'Browser';
  if (/Edg\//.test(ua)) browser = 'Edge';
  else if (/OPR\/|Opera/.test(ua)) browser = 'Opera';
  else if (/Firefox\//.test(ua)) browser = 'Firefox';
  else if (/Chrome\//.test(ua)) browser = 'Chrome';
  else if (/Safari\//.test(ua)) browser = 'Safari';

  let os = 'Unknown OS';
  if (/Windows/.test(ua)) os = 'Windows';
  else if (/Android/.test(ua)) os = 'Android';
  else if (/iPhone|iPad|iPod/.test(ua)) os = 'iOS';
  else if (/Mac OS X|Macintosh/.test(ua)) os = 'macOS';
  else if (/Linux/.test(ua)) os = 'Linux';
  return `${browser} on ${os}`;
}

export function clientInfo(req) {
  return { ipHash: hashIp(req.ip), deviceLabel: deviceLabel(req.get('user-agent')) };
}

// File: server/src/utils/device.js
// End of file