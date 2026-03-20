import { createPublicKey, type JsonWebKey } from 'crypto'
import jwt from 'jsonwebtoken'

const APPLE_KEYS_URL = 'https://appleid.apple.com/auth/keys'
const DEFAULT_CACHE_TTL_MS = 1000 * 60 * 60

interface AppleJwk extends JsonWebKey {
  alg: string
  e: string
  kid: string
  kty: 'RSA'
  n: string
}

interface AppleJwks {
  keys: AppleJwk[]
}

interface AppleKey {
  alg: jwt.Algorithm
  pub: string
}

interface CachedKeys {
  fetchedAt: number
  keys: Map<string, AppleKey>
}

interface AppleVerifierOptions {
  cacheTtlMs?: number
  fetch?: FetchLike
  now?: () => number
}

interface FetchResponse {
  json(): Promise<unknown>
  ok: boolean
  status: number
}

type FetchLike = (input: string) => Promise<FetchResponse>

function jwkToPem(jwk: AppleJwk) {
  return createPublicKey({
    key: { e: jwk.e, kty: jwk.kty, n: jwk.n },
    format: 'jwk',
  })
    .export({ format: 'pem', type: 'pkcs1' })
    .toString()
}

async function fetchKeys(fetchImpl: FetchLike, now: () => number): Promise<CachedKeys> {
  const response = await fetchImpl(APPLE_KEYS_URL)
  if (!response.ok) {
    throw new Error(`failed to fetch apple keys: ${response.status}`)
  }
  const jwks = (await response.json()) as Partial<AppleJwks>
  if (!Array.isArray(jwks.keys)) {
    throw new Error('invalid apple jwks')
  }

  const keys = new Map<string, AppleKey>()
  for (const key of jwks.keys) {
    if (key.kty !== 'RSA' || !key.kid || !key.alg || !key.n || !key.e) continue
    keys.set(key.kid, { alg: key.alg as jwt.Algorithm, pub: jwkToPem(key) })
  }
  if (!keys.size) {
    throw new Error('apple jwks is empty')
  }

  return { fetchedAt: now(), keys }
}

export function createAppleVerifier({
  cacheTtlMs = DEFAULT_CACHE_TTL_MS,
  fetch: fetchImpl = input => fetch(input),
  now = Date.now,
}: AppleVerifierOptions = {}) {
  let cached: CachedKeys | undefined
  let pending: Promise<CachedKeys> | undefined

  async function loadKeys(forceRefresh = false) {
    if (!forceRefresh && cached && now() - cached.fetchedAt < cacheTtlMs) {
      return cached.keys
    }

    if (!pending) {
      pending = fetchKeys(fetchImpl, now)
        .then(next => {
          cached = next
          return next
        })
        .finally(() => {
          pending = undefined
        })
    }

    try {
      return (await pending).keys
    } catch (error) {
      if (!forceRefresh && cached) {
        return cached.keys
      }
      throw error
    }
  }

  async function keyAt(id: string) {
    const key = (await loadKeys()).get(id)
    if (key) return key
    return (await loadKeys(true)).get(id)
  }

  return async function verify(token: string, app: string) {
    const decoded = jwt.decode(token, { complete: true })
    const id = typeof decoded === 'string' ? undefined : decoded?.header.kid
    if (!id) throw 'invalid jwt'

    const key = await keyAt(id)
    if (!key) throw 'key not found'

    const payload = jwt.verify(token, key.pub, {
      algorithms: [key.alg],
      audience: app,
      issuer: 'https://appleid.apple.com',
    })
    if (typeof payload === 'string') throw 'invalid jwt'
    return payload
  }
}

export const verify = createAppleVerifier()
