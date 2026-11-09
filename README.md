# Verity — privacy-first passkey demo

This static landing page includes an optional passkey demonstration at `/passkeys` (`/passkeys.html`). Passkeys use WebAuthn: the browser/device handles biometric or screen-lock verification, and the server stores only credential public keys and counters. The email is only a demo account label; it does not prove legal identity or email ownership.

## Deploy on Netlify

1. Connect this repository to Netlify and deploy the feature branch (or merge it into the deployment branch).
2. Netlify Functions require Node.js 20+ and the dependencies in `package.json`. Netlify Blobs provides persistent credential storage; on a deployed Netlify site it uses the site's configured Blobs storage.
3. In **Site configuration → Environment variables**, set:
   - `WEBAUTHN_ORIGIN` to the exact HTTPS origin, for example `https://your-site-name.netlify.app` (no trailing slash).
   - `WEBAUTHN_RP_ID` to exactly that origin's hostname, for example `your-site-name.netlify.app`.
   - `SESSION_SECRET` to a unique random secret of at least 32 characters. Keep it secret; do not commit it.
4. Redeploy after setting environment variables. Open `/passkeys` on the deployed HTTPS site, register a test passkey, then try the fixed sample transaction. The passkey UI and server endpoints must share the same origin.

For local development, use Netlify Dev and configure matching local `WEBAUTHN_ORIGIN`/`WEBAUTHN_RP_ID` values supported by your WebAuthn browser. Never use a real person's biometric or identity data for testing.

## Important limits

This is a working passkey-authentication demo, **not** a complete identity-proofing or payment system. It does not verify legal identity, prove control of the email address, process or authorize a real payment, or offer account recovery. The successful WebAuthn assertion is associated server-side with the fixed demo order, but the page only displays a sample outcome. Before production use, add appropriate account recovery, abuse/rate limiting, monitoring, data-retention controls, a real payment integration that independently enforces server-side authorization, security testing, and privacy/legal/accessibility review. Do not collect or store biometric templates.
