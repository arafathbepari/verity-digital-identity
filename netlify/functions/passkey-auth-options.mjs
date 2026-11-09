import { generateAuthenticationOptions } from '@simplewebauthn/server';
import { config, fail, json, normalizedEmail, readBody, store, issueChallenge, transaction, userKey } from './passkey-shared.mjs';

export default async (request) => {
  if (request.method !== 'POST') return fail('Method not allowed.', 405);
  try {
    const { rpID } = config(request);
    const { email: rawEmail } = await readBody(request);
    const email = normalizedEmail(rawEmail);
    const user = await store.get(`user:${userKey(email)}`, { type: 'json' });
    if (!user?.credentials?.length) return fail('No demo passkey was found for that account. Register one first.', 404);
    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: user.credentials.map((credential) => ({ id: credential.id, transports: credential.transports })),
      userVerification: 'required'
    });
    const challenge = await issueChallenge(request, 'authentication', {
      challenge: options.challenge,
      email,
      userId: user.id,
      transaction
    });
    return json({ options }, 200, { 'Set-Cookie': challenge.cookie });
  } catch (error) {
    return fail(error.message || 'Could not start passkey verification.', error.message?.includes('not configured') ? 503 : 400);
  }
};
