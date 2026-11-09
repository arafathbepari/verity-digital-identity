import { generateRegistrationOptions } from '@simplewebauthn/server';
import { config, fail, json, normalizedEmail, randomId, readBody, store, issueChallenge, userKey } from './passkey-shared.mjs';

export default async (request) => {
  if (request.method !== 'POST') return fail('Method not allowed.', 405);
  try {
    const { rpID } = config(request);
    const { email: rawEmail } = await readBody(request);
    const email = normalizedEmail(rawEmail);
    const key = `user:${userKey(email)}`;
    let user = await store.get(key, { type: 'json' });
    if (!user) {
      user = { id: randomId(32), email, credentials: [], createdAt: new Date().toISOString() };
      await store.setJSON(key, user);
    }
    const options = await generateRegistrationOptions({
      rpName: 'Verity',
      rpID,
      userID: Buffer.from(user.id, 'base64url'),
      userName: email,
      userDisplayName: 'Verity demo account',
      attestationType: 'none',
      excludeCredentials: user.credentials.map((credential) => ({
        id: credential.id,
        transports: credential.transports
      })),
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'required'
      }
    });
    const challenge = await issueChallenge(request, 'registration', { challenge: options.challenge, email, userId: user.id });
    return json({ options }, 200, { 'Set-Cookie': challenge.cookie });
  } catch (error) {
    return fail(error.message || 'Could not start passkey registration.', error.message?.includes('not configured') ? 503 : 400);
  }
};
