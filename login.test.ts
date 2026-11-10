import { describe, expect, test } from 'bun:test'
import { generateKeyPairSync, type JsonWebKey } from 'crypto'
import jwt from 'jsonwebtoken'
import { createAppleVerifier } from './login'

const app = 'com.example.app'

interface SigningKey {
  kid: string
  privateKey: string
  publicJwk: {
    alg: string
    e: string
    kid: string
    kty: 'RSA'
    n: string
  }
}

function createSigningKey(kid: string): SigningKey {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const jwk = publicKey.export({ format: 'jwk' }) as JsonWebKey
  if (!jwk.n || !jwk.e) {
    throw new Error('failed to export public key')
  }

  return {
    kid,
    privateKey: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    publicJwk: {
      alg: 'RS256',
      e: jwk.e,
      kid,
      kty: 'RSA',
      n: jwk.n,
    },
  }
}

function signToken(privateKey: string, kid: string) {
  return jwt.sign({ sub: kid }, privateKey, {
    algorithm: 'RS256',
    audience: app,
    expiresIn: '5m',
    header: { alg: 'RS256', kid },
    issuer: 'https://appleid.apple.com',
  })
}

function jsonResponse(body: unknown): Response {
  return {
    json: async () => body,
    ok: true,
    status: 200,
  } as Response
}

describe('createAppleVerifier', () => {
  test('reuses cached keys while the cache is still fresh', async () => {
    const key = createSigningKey('kid-1')
    let fetchCalls = 0
    let currentTime = 0
    const verify = createAppleVerifier({
      cacheTtlMs: 1000,
      fetch: async () => {
        fetchCalls += 1
        return jsonResponse({ keys: [key.publicJwk] })
      },
      now: () => currentTime,
    })

    const token = signToken(key.privateKey, key.kid)
    await expect(verify(token, app)).resolves.toMatchObject({ sub: key.kid })

    currentTime = 999
    await expect(verify(token, app)).resolves.toMatchObject({ sub: key.kid })
    expect(fetchCalls).toBe(1)
  })

  test('refreshes keys when Apple rotates to a new kid', async () => {
    const firstKey = createSigningKey('kid-1')
    const secondKey = createSigningKey('kid-2')
    let fetchCalls = 0
    const verify = createAppleVerifier({
      fetch: async () => {
        fetchCalls += 1
        return jsonResponse({
          keys: [fetchCalls === 1 ? firstKey.publicJwk : secondKey.publicJwk],
        })
      },
    })

    await expect(verify(signToken(firstKey.privateKey, firstKey.kid), app)).resolves.toMatchObject({
      sub: firstKey.kid,
    })
    await expect(verify(signToken(secondKey.privateKey, secondKey.kid), app)).resolves.toMatchObject({
      sub: secondKey.kid,
    })
    expect(fetchCalls).toBe(2)
  })

  test('falls back to stale keys during a refresh failure', async () => {
    const key = createSigningKey('kid-1')
    let fetchCalls = 0
    let currentTime = 0
    const verify = createAppleVerifier({
      cacheTtlMs: 1000,
      fetch: async () => {
        fetchCalls += 1
        if (fetchCalls > 1) {
          throw new Error('network down')
        }
        return jsonResponse({ keys: [key.publicJwk] })
      },
      now: () => currentTime,
    })

    const token = signToken(key.privateKey, key.kid)
    await expect(verify(token, app)).resolves.toMatchObject({ sub: key.kid })

    currentTime = 1001
    await expect(verify(token, app)).resolves.toMatchObject({ sub: key.kid })
    expect(fetchCalls).toBe(2)
  })

  test('fetches again for unknown key ids at most once a minute', async () => {
    const key = createSigningKey('kid-1')
    const stranger = createSigningKey('kid-unknown')
    let fetchCalls = 0
    let currentTime = 0
    const verify = createAppleVerifier({
      fetch: async () => {
        fetchCalls += 1
        return jsonResponse({ keys: [key.publicJwk] })
      },
      now: () => currentTime,
    })

    await expect(verify(signToken(key.privateKey, key.kid), app)).resolves.toMatchObject({ sub: key.kid })
    for (let i = 0; i < 5; i++) {
      await expect(verify(signToken(stranger.privateKey, stranger.kid), app)).rejects.toBe('key not found')
    }
    expect(fetchCalls).toBe(2)

    currentTime = 60_000
    await expect(verify(signToken(stranger.privateKey, stranger.kid), app)).rejects.toBe('key not found')
    expect(fetchCalls).toBe(3)
  })

  test('refuses a call without an app, which would skip the audience check', async () => {
    const key = createSigningKey('kid-1')
    const verify = createAppleVerifier({ fetch: async () => jsonResponse({ keys: [key.publicJwk] }) })
    const token = signToken(key.privateKey, key.kid)
    await expect(verify(token, undefined as unknown as string)).rejects.toBe('app required')
    await expect(verify(token, '')).rejects.toBe('app required')
    await expect(verify(token, 'com.other.app')).rejects.toThrow('jwt audience invalid')
  })
})
