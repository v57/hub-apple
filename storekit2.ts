import jwt from 'jsonwebtoken'
import { X509 } from 'jsrsasign'

export function decode(signedInfo: string) {
  function generateCertificate(cert: any) {
    // A simple function just like the PHP's chunk_split, used in generating pem.
    function chunk_split(body: string, chunklen: number, end: string) {
      return body.match(new RegExp('.{0,' + chunklen + '}', 'g'))?.join(end)
    }
    const data = chunk_split(cert, 64, '\n')
    if (!data) throw 'invalid info'
    const x509 = new X509()
    x509.readCertPEM(`-----BEGIN CERTIFICATE-----\n${data}-----END CERTIFICATE-----`)
    return x509
  }

  // The signed info are in three parts as specified by Apple
  const parts = signedInfo.split('.')
  if (parts.length !== 3) {
    throw 'The data structure is wrong! Check it! '
  }
  // All the information needed for verification is in the header
  const header = JSON.parse(Buffer.from(parts[0], 'base64').toString())

  // The chained certificates
  const certificates = header.x5c.map((cert: any) => generateCertificate(cert))
  const chainLength = certificates.length

  // Leaf certificate is the last one
  const leafCert = header.x5c[chainLength - 1]
  // Download .cer file at https://www.apple.com/certificateauthority/. Convert to pem file with this command line: openssl x509 -inform der -in AppleRootCA-G3.cer -out AppleRootCA-G3.pem
  const AppleRootCA =
    'MIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTQwNDMwMTgxOTA2WhcNMzkwNDMwMTgxOTA2WjBnMRswGQYDVQQDDBJBcHBsZSBSb290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABJjpLz1AcqTtkyJygRMc3RCV8cWjTnHcFBbZDuWmBSp3ZHtfTjjTuxxEtX/1H7YyYl3J6YRbTzBPEVoA/VhYDKX1DyxNB0cTddqXl5dvMVztK517IDvYuVTZXpmkOlEKMaNCMEAwHQYDVR0OBBYEFLuw3qFYM4iapIqZ3r6966/ayySrMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gAMGUCMQCD6cHEFl4aXTQY2e3v9GwOAEZLuN+yRhHFD/3meoyhpmvOwgPUnPWTxnS4at+qIxUCMG1mihDK1A3UT82NQz60imOlM27jbdoXt2QfyFMm+YhidDkLF1vLUagM6BgD56KyKA=='

  // The leaf cert should be the same as the Apple root cert
  const isLeafCertValid = AppleRootCA === leafCert
  if (!isLeafCertValid) {
    throw 'Leaf cert not valid!'
  }

  // MARK: If there are more than one certificates in the chain, we need to verify them one by one
  if (chainLength > 1) {
    for (var i = 0; i < chainLength - 1; i++) {
      const isCertValid = certificates[i].verifySignature(certificates[i + 1].getPublicKey())
      if (!isCertValid) {
        throw `Cert ${i} not valid! `
      }
    }
  }

  return jwt.decode(signedInfo)
}
