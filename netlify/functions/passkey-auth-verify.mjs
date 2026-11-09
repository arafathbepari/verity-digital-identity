import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import { config, consumeChallenge, fail, json, readBody, sessionCookie, store, transaction, userKey } from './passkey-shared.mjs';

export default async (request) => {
  if (request.method !== 'POST') return fail('Method not allowed.', 405);
  try {
    const { expectedOrigin, rpID } = config(request);
    const challenge = await consumeChallenge(request, 'authentication');
    if (!challenge) return fail('Verification expired. Please start again.', 400);
    const { response } = await readBody(request);
    const user = await store.get(`user:${userKey(challenge.email)}`, { type: 'json' });
    if (!user || user.id !== challenge.userId) return fail('The demo account was not found.', 400);
    const index = user.credentials.findIndex((credential) => credential.id === response.id);
    if (index < 0) return fail('That passkey is not registered to this demo account.', 400);
    const saved = user.credentials[index];
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challenge.challenge,
      expectedOrigin,
      expectedRPID: rpID,
      requireUserVerification: true,
      authenticator: {
        credentialID: Buffer.from(saved.id, 'base64url'),
        credentialPublicKey: Buffer.from(saved.publicKey, 'base64url'),
        counter: saved.counter,
        transports: saved.transports
      }
    });
    if (!verification.verified) return fail('Passkey verification failed.', 401);
    user.credentials[index].counter = verification.authenticationInfo.newCounter;
    await store.setJSON(`user:${userKey(challenge.email)}`, user);
    return json({
      verified: true,
      message: 'Passkey verified for this sample request.',
      transaction: challenge.transaction,
      note: 'This demo did not authorize a real payment or charge money.'
    }, 200, { 'Set-Cookie': sessionCookie(user.id) });
  } catch (error) {
    return fail(error.message || 'Passkey verification failed.', error.message?.includes('not configured') ? 503 : 400);
  }
};
