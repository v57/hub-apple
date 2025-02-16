import jwt from 'jsonwebtoken'

async function tryKeys() {
  const response = await fetch('https://appleid.apple.com/auth/keys')
  const jwks = await response.json()
  let keys = new Map()
  jwks.keys.forEach((key: any) => {
    keys.set(key.kid, { pub: jwkToPem(key), alg: key.alg })
  })
  return keys
}
let _keys: Promise<Map<string, { pub: string; alg: string }>> | undefined
function keys() {
  if (!_keys) _keys = tryKeys()
  return _keys
}
async function keyAt(id: string) {
  try {
    const resolve = await keys()
    return resolve.get(id)
  } catch {
    _keys = undefined
  }
}

function jwkToPem(jwk: any) {
  const { kty, n, e } = jwk
  if (kty !== 'RSA') {
    console.log('Key type must be RSA. Instead of', kty)
  }

  // Buffer to hold the decoded data
  const modulus = Buffer.from(n, 'base64')
  const exponent = Buffer.from(e, 'base64')

  // Construct the PEM
  const der = Buffer.concat([
    Buffer.from([0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00]), // SEQUENCE and INTEGER
    modulus,
    Buffer.from([0x02, 0x03]), // INTEGER
    exponent,
    Buffer.from([0x00]),
  ])

  return `-----BEGIN ${kty} PUBLIC KEY-----\n${der.toString('base64')}\n-----END ${kty} PUBLIC KEY-----`
}

interface Decoded {
  exp: string
  iss: string
  aud: string
}

export async function verify(token: string, app: string) {
  const id = jwt.decode(token, { complete: true })?.header.kid
  if (!id) throw 'invalid jwt'
  const key = await keyAt(id)
  if (!key) throw 'key not found'
  const a = jwt.verify(token, key.pub, { algorithms: [key.alg as jwt.Algorithm] })
  if (typeof a == 'string') throw 'invalid jwt'
  if (a.exp && new Date().getTime() / 1000 > a.exp) throw 'token expired'
  if (a.iss !== 'https://appleid.apple.com') throw 'invalid token'
  if (a.aud !== app) throw 'invalid token'
  return a
}
