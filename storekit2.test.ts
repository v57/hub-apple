import { describe, expect, test } from 'bun:test'
import { generateKeyPairSync, sign, type KeyObject } from 'crypto'
import { KJUR, KEYUTIL } from 'jsrsasign'
import { APPLE_ROOT_CA_G3, RECEIPT_SIGNING_OID, WWDR_INTERMEDIATE_OID, createStoreKitVerifier, decode } from './storekit2'

// A chain shaped like Apple's (P-384 root, intermediate with the WWDR OID, P-256 leaf with the receipt-signing OID),
// made here and trusted through the verifier's injectable roots

interface Key {
  private: KeyObject
  pem: { private: string; public: string }
}

function key(namedCurve: 'P-256' | 'P-384'): Key {
  const pair = generateKeyPairSync('ec', { namedCurve })
  return {
    private: pair.privateKey,
    pem: {
      private: pair.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
      public: pair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    },
  }
}

interface CertOptions {
  subject: string
  issuer: string
  subjectKey: Key
  issuerKey: Key
  ca?: boolean
  oid?: string
  notBefore?: string
  notAfter?: string
}

function cert(options: CertOptions) {
  const ext: any[] = [{ extname: 'basicConstraints', cA: options.ca ?? false }]
  if (options.oid) ext.push({ extname: options.oid, extn: '0500' })
  const certificate = new KJUR.asn1.x509.Certificate({
    version: 3,
    serial: { int: Math.floor(Math.random() * 1e9) },
    issuer: { str: options.issuer },
    subject: { str: options.subject },
    notbefore: { str: options.notBefore ?? '200101000000Z' },
    notafter: { str: options.notAfter ?? '491231235959Z' },
    sbjpubkey: KEYUTIL.getKey(options.subjectKey.pem.public),
    ext,
    sigalg: 'SHA256withECDSA',
    cakey: KEYUTIL.getKey(options.issuerKey.pem.private),
  } as any)
  return Buffer.from((certificate as any).tohex(), 'hex').toString('base64')
}

const rootKey = key('P-384')
const intermediateKey = key('P-384')
const leafKey = key('P-256')
const root = cert({ subject: '/CN=Test Root CA', issuer: '/CN=Test Root CA', subjectKey: rootKey, issuerKey: rootKey, ca: true })
const intermediate = cert({
  subject: '/CN=Test WWDR',
  issuer: '/CN=Test Root CA',
  subjectKey: intermediateKey,
  issuerKey: rootKey,
  ca: true,
  oid: WWDR_INTERMEDIATE_OID,
})
const leaf = cert({ subject: '/CN=Test StoreKit', issuer: '/CN=Test WWDR', subjectKey: leafKey, issuerKey: intermediateKey, oid: RECEIPT_SIGNING_OID })

const signedDate = Date.parse('2026-11-01T00:00:00Z')
const transaction = {
  transactionId: '2000000000000001',
  originalTransactionId: '2000000000000001',
  bundleId: 'com.example.app',
  productId: 'pro.lifetime',
  purchaseDate: signedDate,
  signedDate,
  environment: 'Sandbox',
}

const b64url = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url')

function jws(payload: unknown, x5c: string[], signer: Key = leafKey, alg = 'ES256') {
  const signing = `${b64url({ alg, x5c })}.${b64url(payload)}`
  const signature = sign('sha256', Buffer.from(signing), { key: signer.private, dsaEncoding: 'ieee-p1363' })
  return `${signing}.${signature.toString('base64url')}`
}

const verifier = createStoreKitVerifier({ roots: [root] })

describe('apple/storekit2', () => {
  test('accepts a transaction signed by a leaf that chains to a trusted root', () => {
    expect(verifier(jws(transaction, [leaf, intermediate, root]))).toEqual(transaction)
  })

  test('refuses a forged payload carrying a genuine chain', () => {
    // The chain is valid, but the JWS is signed by a key that isn't the leaf's
    const forged = jws({ ...transaction, productId: 'pro.forever' }, [leaf, intermediate, root], key('P-256'))
    expect(() => verifier(forged)).toThrow('invalid jws signature')
  })

  test('refuses a genuine signature over a swapped payload', () => {
    const [header, , signature] = jws(transaction, [leaf, intermediate, root]).split('.')
    const swapped = `${header}.${b64url({ ...transaction, productId: 'pro.forever' })}.${signature}`
    expect(() => verifier(swapped)).toThrow('invalid jws signature')
  })

  test('refuses the old forge: a one-certificate chain of the real Apple root', () => {
    // network.md H6: x5c [AppleRoot] used to pass, and the payload came back unchecked
    expect(() => decode(jws(transaction, [APPLE_ROOT_CA_G3]))).toThrow('invalid certificate chain')
    expect(() => decode(jws(transaction, [leaf, intermediate, APPLE_ROOT_CA_G3]))).toThrow('certificate chain does not end at a trusted root')
  })

  test('refuses a chain whose root is not trusted, even when it is sent', () => {
    const otherRootKey = key('P-384')
    const otherRoot = cert({ subject: '/CN=Test Root CA', issuer: '/CN=Test Root CA', subjectKey: otherRootKey, issuerKey: otherRootKey, ca: true })
    const otherIntermediate = cert({
      subject: '/CN=Test WWDR',
      issuer: '/CN=Test Root CA',
      subjectKey: intermediateKey,
      issuerKey: otherRootKey,
      ca: true,
      oid: WWDR_INTERMEDIATE_OID,
    })
    expect(() => verifier(jws(transaction, [leaf, otherIntermediate, otherRoot]))).toThrow('certificate chain does not end at a trusted root')
  })

  test('refuses a reversed chain (the root first)', () => {
    expect(() => verifier(jws(transaction, [root, intermediate, leaf]))).toThrow()
  })

  test('refuses a leaf without the receipt-signing OID', () => {
    const plainLeaf = cert({ subject: '/CN=Test StoreKit', issuer: '/CN=Test WWDR', subjectKey: leafKey, issuerKey: intermediateKey })
    expect(() => verifier(jws(transaction, [plainLeaf, intermediate, root]))).toThrow('leaf certificate is not for App Store signing')
  })

  test('refuses an intermediate without the WWDR OID', () => {
    const plainIntermediate = cert({ subject: '/CN=Test WWDR', issuer: '/CN=Test Root CA', subjectKey: intermediateKey, issuerKey: rootKey, ca: true })
    expect(() => verifier(jws(transaction, [leaf, plainIntermediate, root]))).toThrow('intermediate certificate is not Apple\'s')
  })

  test('refuses an intermediate that is not a CA', () => {
    const notCA = cert({
      subject: '/CN=Test WWDR',
      issuer: '/CN=Test Root CA',
      subjectKey: intermediateKey,
      issuerKey: rootKey,
      oid: WWDR_INTERMEDIATE_OID,
    })
    expect(() => verifier(jws(transaction, [leaf, notCA, root]))).toThrow('intermediate certificate is not a CA')
  })

  test('refuses a leaf signed by someone other than the intermediate', () => {
    const selfSigned = cert({ subject: '/CN=Test StoreKit', issuer: '/CN=Test WWDR', subjectKey: leafKey, issuerKey: leafKey, oid: RECEIPT_SIGNING_OID })
    expect(() => verifier(jws(transaction, [selfSigned, intermediate, root]))).toThrow('leaf certificate not issued by the intermediate')
  })

  test('checks the dates at signedDate', () => {
    const expiredLeaf = cert({
      subject: '/CN=Test StoreKit',
      issuer: '/CN=Test WWDR',
      subjectKey: leafKey,
      issuerKey: intermediateKey,
      oid: RECEIPT_SIGNING_OID,
      notBefore: '240101000000Z',
      notAfter: '250101000000Z',
    })
    expect(() => verifier(jws(transaction, [expiredLeaf, intermediate, root]))).toThrow('certificate expired or not yet valid')
    const signedWhileValid = { ...transaction, signedDate: Date.parse('2024-06-01T00:00:00Z') }
    expect(verifier(jws(signedWhileValid, [expiredLeaf, intermediate, root]))).toEqual(signedWhileValid)
  })

  test('uses now without a signedDate', () => {
    const { signedDate: _, ...unsigned } = transaction
    const at = (time: string) => createStoreKitVerifier({ roots: [root], now: () => Date.parse(time) })
    expect(at('2030-01-01T00:00:00Z')(jws(unsigned, [leaf, intermediate, root]))).toEqual(unsigned)
    expect(() => at('2050-01-01T00:00:00Z')(jws(unsigned, [leaf, intermediate, root]))).toThrow('certificate expired or not yet valid')
  })

  test('refuses other algorithms and malformed input', () => {
    expect(() => verifier(jws(transaction, [leaf, intermediate, root], leafKey, 'none'))).toThrow('invalid jws algorithm')
    expect(() => verifier('a.b')).toThrow('invalid jws')
    expect(() => verifier({})).toThrow('invalid jws')
    expect(() => verifier(jws(transaction, [leaf, intermediate]))).toThrow('invalid certificate chain')
    expect(() => verifier(jws(transaction, ['not a certificate', intermediate, root]))).toThrow('invalid leaf certificate')
  })
})
