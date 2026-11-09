import { verifyRegistrationResponse } from '@simplewebauthn/server';
import { config, consumeChallenge, fail, json, readBody, store, userKey } from './passkey-shared.mjs';

export default async (request) => {
  if (request.method !== 'POST') return fail('Method not allowed.', 405);
  try {
    const { expectedOrigin, rpID } = config(request);
    const challenge = await consumeChallenge(request, 'registration');
    if (!challenge) return fail('Registration expired. Please start again.', 400);
    const { response } = await readBody(request);
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: challenge.challenge,
      expectedOrigin,
      expectedRPID: rpID,
      requireUserVerification: true
    });
    if (!verification.verified || !verification.registrationInfo) return fail('Passkey registration could not be verified.', 400);

    const info = verification.registrationInfo;
    const credential = info.credential || {
      id: Buffer.from(info.credentialID).toString('base64url'),
      publicKey: info.credentialPublicKey,
      counter: info.counter,
      transports: response.response?.transports || []
    };
    const key = `user:${userKey(challenge.email)}`;
    const user = await store.get(key, { type: 'json' });
    if (!user || user.id !== challenge.userId) return fail('Demo account changed. Please start again.', 400);
    if (user.credentials.some((saved) => saved.id === credential.id)) return fail('This passkey is already registered.', 409);
    user.credentials.push({
      id: credential.id,
      publicKey: Buffer.from(credential.publicKey).toString('base64url'),
      counter: credential.counter,
      transports: credential.transports || response.response?.transports || []
    });
    await store.setJSON(key, user);
    return json({ verified: true, message: 'Passkey registered. Your device keeps the biometric; Verity stores a public key.' });
  } catch (error) {
    return fail(error.message || 'Passkey registration failed.', 400);
  }
};
