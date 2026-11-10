/**
 * What a path says about itself in `hub/api/list` (protocol.md section 15): passed in the settings of `post` and
 * `stream`, next to `access`. hub-service before descriptions ignores these fields.
 */
export interface Described {
  title?: string
  description: string
  inputSchema?: Record<string, unknown>
  outputSchema?: Record<string, unknown>
  annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean; idempotentHint?: boolean; openWorldHint?: boolean }
}
// Typed, not `satisfies`: schema literals would widen to `type: string`, which ApiSettings' JSONSchema doesn't take
export type Descriptions = { post: Record<string, Described>; stream: Record<string, Described> }

const login = {
  type: 'object',
  properties: {
    token: { type: 'string', description: 'The identity token (a JWT) Sign in with Apple gave the app' },
    app: { type: 'string', description: 'The app\'s bundle id or Services ID, which the token\'s audience must match' },
  },
  required: ['token', 'app'],
}
const failures = 'Fails with "invalid jwt", "key not found" (no Apple key with the token\'s kid), or the verification error for a bad signature, audience, issuer or expiry.'

export const descriptions: Descriptions = {
  post: {
    'apple/login': {
      title: 'Verify Sign in with Apple',
      description: `Verifies a Sign in with Apple identity token against Apple's published keys (cached for an hour) and answers its claims. ${failures}`,
      inputSchema: login,
      outputSchema: {
        type: 'object',
        description: 'The token\'s claims',
        properties: {
          sub: { type: 'string', description: 'The user\'s stable id for this team' },
          email: { type: 'string', description: 'Present when the user shared it, possibly a private relay address' },
          email_verified: { type: ['boolean', 'string'] },
          is_private_email: { type: ['boolean', 'string'] },
          aud: { type: 'string' },
          iss: { type: 'string', const: 'https://appleid.apple.com' },
          iat: { type: 'integer' },
          exp: { type: 'integer' },
        },
        required: ['sub', 'aud', 'iss'],
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    'apple/login/lite': {
      title: 'Sign in with Apple user id',
      description: `Verifies a Sign in with Apple identity token like apple/login and answers only the user id (the sub claim). ${failures}`,
      inputSchema: login,
      outputSchema: { type: 'string', description: 'The user\'s stable id (sub)' },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    'apple/storekit2': {
      title: 'Decode a StoreKit 2 transaction',
      description:
        'Verifies a StoreKit 2 signed transaction, renewal info or notification (JWS) as Apple\'s App Store Server Library does without online checks: ES256 signed by the leaf certificate, a leaf, intermediate and root chain to Apple Root CA G3 with Apple\'s OIDs, every certificate valid at signedDate. Answers the payload; the caller checks bundleId and environment. Fails with "invalid jws", "invalid certificate chain", "invalid jws signature" and similar.',
      inputSchema: { type: 'string', description: 'The signed transaction (JWS) from StoreKit 2 or App Store Server Notifications' },
      outputSchema: {
        type: 'object',
        description: 'The JWS payload, e.g. transactionId, originalTransactionId, productId, bundleId, purchaseDate, expiresDate',
        properties: {
          transactionId: { type: 'string' },
          originalTransactionId: { type: 'string' },
          productId: { type: 'string' },
          bundleId: { type: 'string' },
          purchaseDate: { type: 'integer', description: 'Milliseconds since 1970' },
          expiresDate: { type: 'integer', description: 'Milliseconds since 1970, for subscriptions' },
          environment: { type: 'string', enum: ['Sandbox', 'Production', 'Xcode'] },
        },
      },
      annotations: { readOnlyHint: true },
    },
  },
  stream: {},
}
