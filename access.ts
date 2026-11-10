import type { ApiSettings } from 'hub-service'

/**
 * Who may call each path: anyone, on purpose. Each path verifies a token or a signed transaction the caller presents
 * against Apple's public keys and answers what that data already says. The service holds no secret and changes no
 * state, so a grant protects nothing, and apps' own clients can call it on default-deny hubs. The calls an outsider
 * could make it do are capped: a token naming an unknown Apple key refetches Apple's keys at most once a minute, and
 * hub-service's per-caller rate limit applies. Trust comes from the answer, never from being allowed to ask: a
 * backend checks the audience it passed (`app`) and, for StoreKit, `bundleId` and `environment`.
 */
const anyone: ApiSettings = { public: true }

export const access: Record<string, ApiSettings> = {
  'apple/login': anyone,
  'apple/login/lite': anyone,
  'apple/storekit2': anyone,
}
