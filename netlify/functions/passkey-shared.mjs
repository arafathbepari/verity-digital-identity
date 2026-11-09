import { getStore } from '@netlify/blobs';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export const store = getStore('verity-passkeys');
export const transaction = Object.freeze({ merchant: 'Verity Demo Shop', amount: 'USD $24.00', reference: 'DEMO-1042' });

export function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers }
  });
}

export function fail(message, status = 400) { return json({ error: message }, status); }

export async function readBody(request) {
  try { return await request.json(); } catch { throw new Error('Send a valid JSON request.'); }
}

export function config(request) {
  const expectedOrigin = process.env.WEBAUTHN_ORIGIN;
  const rpID = process.env.WEBAUTHN_RP_ID;
  if (!expectedOrigin || !rpID) throw new Error('Passkey service is not configured. Set WEBAUTHN_ORIGIN and WEBAUTHN_RP_ID.');
  let parsed;
  try { parsed = new URL(expectedOrigin); } catch { throw new Error('WEBAUTHN_ORIGIN must be a valid origin URL.'); }
  if (parsed.origin !== expectedOrigin || parsed.hostname !== rpID || parsed.protocol !== 'https:') {
    throw new Error('Passkey origin settings are invalid. Use the site HTTPS origin and its exact hostname.');
  }
  const origin = request.headers.get('origin');
  if (origin !== expectedOrigin) throw new Error('Request origin is not allowed.');
  return { expectedOrigin, rpID };
}

export function normalizedEmail(email) {
  if (typeof email !== 'string' || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new Error('Enter a valid email address.');
  }
  return email.trim().toLowerCase();
}

export function userKey(email) {
  return createHmac('sha256', process.env.SESSION_SECRET || 'configuration-required').update(email).digest('hex');
}

export function randomId(bytes = 32) { return randomBytes(bytes).toString('base64url'); }

export function cookieValue(request, name) {
  const cookies = request.headers.get('cookie') || '';
  const item = cookies.split(';').map((part) => part.trim()).find((part) => part.startsWith(`${name}=`));
  return item ? decodeURIComponent(item.slice(name.length + 1)) : null;
}

export async function issueChallenge(request, kind, value) {
  const id = randomId();
  await store.setJSON(`challenge:${id}`, { ...value, kind, expiresAt: Date.now() + 5 * 60 * 1000 });
  return { id, cookie: `verity_challenge=${encodeURIComponent(id)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=300` };
}

export async function consumeChallenge(request, kind) {
  const id = cookieValue(request, 'verity_challenge');
  if (!id || !/^[A-Za-z0-9_-]{40,50}$/.test(id)) return null;
  const key = `challenge:${id}`;
  const challenge = await store.get(key, { type: 'json' });
  await store.delete(key);
  if (!challenge || challenge.kind !== kind || challenge.expiresAt < Date.now()) return null;
  return challenge;
}

export function sessionCookie(userId) {
  const secret = process.env.SESSION_SECRET;
  if (!secret || secret.length < 32) throw new Error('Set SESSION_SECRET to a random value of at least 32 characters.');
  const expires = Math.floor(Date.now() / 1000) + 60 * 60;
  const value = `${userId}.${expires}`;
  const signature = createHmac('sha256', secret).update(value).digest('base64url');
  return `verity_session=${encodeURIComponent(`${value}.${signature}`)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600`;
}

export function safeEqual(a, b) {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}
