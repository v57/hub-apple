import { X509Certificate, verify as verifySignature } from 'crypto'
import { X509 } from 'jsrsasign'

/**
 * Apple Root CA G3 (DER, base64), from https://www.apple.com/certificateauthority/. Every StoreKit 2 and App Store
 * Server Notifications JWS chains to it.
 */
export const APPLE_ROOT_CA_G3 =
  'MIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTQwNDMwMTgxOTA2WhcNMzkwNDMwMTgxOTA2WjBnMRswGQYDVQQDDBJBcHBsZSBSb290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABJjpLz1AcqTtkyJygRMc3RCV8cWjTnHcFBbZDuWmBSp3ZHtfTjjTuxxEtX/1H7YyYl3J6YRbTzBPEVoA/VhYDKX1DyxNB0cTddqXl5dvMVztK517IDvYuVTZXpmkOlEKMaNCMEAwHQYDVR0OBBYEFLuw3qFYM4iapIqZ3r6966/ayySrMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gAMGUCMQCD6cHEFl4aXTQY2e3v9GwOAEZLuN+yRhHFD/3meoyhpmvOwgPUnPWTxnS4at+qIxUCMG1mihDK1A3UT82NQz60imOlM27jbdoXt2QfyFMm+YhidDkLF1vLUagM6BgD56KyKA=='

/** Marks a certificate Apple issued for signing App Store receipts and transactions (on the leaf) */
export const RECEIPT_SIGNING_OID = '1.2.840.113635.100.6.11.1'
/** Marks Apple's Worldwide Developer Relations intermediate (on the intermediate) */
export const WWDR_INTERMEDIATE_OID = '1.2.840.113635.100.6.2.1'

export interface StoreKitVerifierOptions {
  /** Trusted roots, DER as base64. Apple Root CA G3 by default; tests pass their own */
  roots?: string[]
  /** The time used when the payload carries no signedDate */
  now?: () => number
}

function certificate(der: unknown, role: string) {
  if (typeof der !== 'string') throw `invalid ${role} certificate`
  try {
    return new X509Certificate(Buffer.from(der, 'base64'))
  } catch {
    throw `invalid ${role} certificate`
  }
}

function hasExtension(cert: X509Certificate, oid: string) {
  const x509 = new X509()
  x509.readCertHex(cert.raw.toString('hex'))
  return x509.getExtInfo(oid) !== undefined
}

function validAt(cert: X509Certificate, date: number) {
  return Date.parse(cert.validFrom) <= date && date <= Date.parse(cert.validTo)
}

/**
 * Verifies a StoreKit 2 JWS (a signed transaction, renewal info or notification) the way Apple's App Store Server
 * Library does without online checks: ES256, an x5c chain of exactly leaf, intermediate and root, the intermediate
 * signed by a trusted root and the leaf by the intermediate, Apple's OIDs on both, every certificate valid at the
 * payload's signedDate, and the JWS signature checked with the leaf's key. Answers the payload.
 *
 * It doesn't know the caller's app: the caller checks `bundleId` (and `environment`) in the answer.
 */
export function createStoreKitVerifier({ roots = [APPLE_ROOT_CA_G3], now = Date.now }: StoreKitVerifierOptions = {}) {
  const trusted = roots.map(root => certificate(root, 'root'))

  return function decode(signedInfo: unknown): Record<string, unknown> {
    if (typeof signedInfo !== 'string') throw 'invalid jws'
    const parts = signedInfo.split('.')
    if (parts.length !== 3) throw 'invalid jws'
    const [encodedHeader, encodedPayload, encodedSignature] = parts

    let header: { alg?: unknown; x5c?: unknown }
    try {
      header = JSON.parse(Buffer.from(encodedHeader, 'base64url').toString())
    } catch {
      throw 'invalid jws'
    }
    if (header?.alg !== 'ES256') throw 'invalid jws algorithm'
    if (!Array.isArray(header.x5c) || header.x5c.length !== 3) throw 'invalid certificate chain'

    // x5c lists the leaf first, then the intermediate, then the root (RFC 7515 4.1.6). The root sent is not used:
    // the intermediate must be issued by one of the trusted roots.
    const leaf = certificate(header.x5c[0], 'leaf')
    const intermediate = certificate(header.x5c[1], 'intermediate')
    const root = trusted.find(root => intermediate.checkIssued(root) && intermediate.verify(root.publicKey))
    if (!root) throw 'certificate chain does not end at a trusted root'
    if (!intermediate.ca) throw 'intermediate certificate is not a CA'
    if (!leaf.checkIssued(intermediate) || !leaf.verify(intermediate.publicKey)) throw 'leaf certificate not issued by the intermediate'
    if (!hasExtension(leaf, RECEIPT_SIGNING_OID)) throw 'leaf certificate is not for App Store signing'
    if (!hasExtension(intermediate, WWDR_INTERMEDIATE_OID)) throw 'intermediate certificate is not Apple\'s'

    const key = leaf.publicKey
    if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') throw 'leaf key is not P-256'
    const signature = Buffer.from(encodedSignature, 'base64url')
    const signed = Buffer.from(`${encodedHeader}.${encodedPayload}`)
    if (signature.length !== 64 || !verifySignature('sha256', signed, { key, dsaEncoding: 'ieee-p1363' }, signature)) {
      throw 'invalid jws signature'
    }

    let payload: unknown
    try {
      payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString())
    } catch {
      throw 'invalid jws payload'
    }
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw 'invalid jws payload'
    const record = payload as Record<string, unknown>

    // Apple's library checks the dates at signedDate (receiptCreationDate for app transactions) when it makes no
    // online revocation check, so a transaction signed while the leaf was valid stays valid
    const signedDate = record.signedDate ?? record.receiptCreationDate
    const effectiveDate = typeof signedDate === 'number' ? signedDate : now()
    if (![leaf, intermediate, root].every(cert => validAt(cert, effectiveDate))) throw 'certificate expired or not yet valid'

    return record
  }
}

export const decode = createStoreKitVerifier()
