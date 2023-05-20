import {ECDSA, Curve, Key, EC_CURVE} from "../src"

describe("ECDSA", () => {
  let ecdsa

  beforeEach(() => {
    ecdsa = new ECDSA(Curve.secp256k1)
  })

  test("throws error for unsupported curve", () => {
    expect(() => new ECDSA("unsupportedCurve" as EC_CURVE)).toThrow("Unsupported curve: unsupportedCurve.")
  })

  test(" generate key pair", () => {
    ecdsa.genKeyPair()

    expect(ecdsa.privateKey).toBeDefined()
    expect(ecdsa.publicKey).toBeDefined()
  })

  test("exports private key to DER format", () => {
    ecdsa.genKeyPair()
    const privateKeyDER = ecdsa.toDER(Key.privateKey)

    expect(privateKeyDER).toBeDefined()
    expect(typeof privateKeyDER).toEqual("object")
  })

  test("exports private key to PEM format", () => {
    ecdsa.genKeyPair()
    const privateKeyPEM = ecdsa.toPEM(Key.privateKey)

    expect(privateKeyPEM).toBeDefined()
    expect(typeof privateKeyPEM).toEqual("string")
  })

  test(" sign message", () => {
    ecdsa.genKeyPair()
    const message = "test message"
    const signature = ecdsa.sign(message)

    expect(signature).toBeDefined()
  })

  test("verifies signature", () => {
    ecdsa.genKeyPair()
    const message = "test message"
    const signature = ecdsa.sign(message)

    expect(ecdsa.verify(message, signature)).toBeTruthy()
  })

  test("throws error when private key is not set for signing", () => {
    const message = "test message"

    expect(() => ecdsa.sign(message)).toThrow("No private key set")
  })

  test("throws error when public key is not set for verification", () => {
    const message = "test message"
    const signature = "test signature" // TODO: replace with actual signature

    expect(() => ecdsa.verify(message, signature)).toThrow("No public key set")
  })


  test("converts correctly from PEM to DER and back to PEM for private key", () => {
    ecdsa.genKeyPair()
    const originalPrivateKeyPEM = ecdsa.toPEM(Key.privateKey)

    const privateKeyDER = ecdsa.toDER(Key.privateKey)
    const ecdsa2 = ECDSA.withCurve(Curve.secp256k1)
    ecdsa2.fromDER(privateKeyDER, Key.privateKey)
    const convertedPrivateKeyPEM = ecdsa2.toPEM(Key.privateKey)

    expect(convertedPrivateKeyPEM).toEqual(originalPrivateKeyPEM)
  })

  test("converts correctly from DER to PEM and back to DER for private key", () => {
    ecdsa.genKeyPair()
    const originalPrivateKeyDER = ecdsa.toDER(Key.privateKey)

    const privateKeyPEM = ecdsa.toPEM(Key.privateKey)
    const ecdsa2 = ECDSA.withCurve(Curve.secp256k1)
    ecdsa2.fromPEM(privateKeyPEM, Key.privateKey)
    const convertedPrivateKeyDER = ecdsa2.toDER(Key.privateKey)

    expect(convertedPrivateKeyDER).toEqual(originalPrivateKeyDER)
  })

  test("converts correctly from PEM to DER and back to PEM for public key", () => {
    ecdsa.genKeyPair()
    const originalPublicKeyPEM = ecdsa.toPEM(Key.publicKey)

    const publicKeyDER = ecdsa.toDER(Key.publicKey)
    const ecdsa2 = ECDSA.withCurve(Curve.secp256k1)
    ecdsa2.fromDER(publicKeyDER, Key.publicKey)
    const convertedPublicKeyPEM = ecdsa2.toPEM(Key.publicKey)

    expect(convertedPublicKeyPEM).toEqual(originalPublicKeyPEM)
  })

  test("converts correctly from DER to PEM and back to DER for public key", () => {
    ecdsa.genKeyPair()
    const originalPublicKeyDER = ecdsa.toDER(Key.publicKey)

    const publicKeyPEM = ecdsa.toPEM(Key.publicKey)
    const ecdsa2 = ECDSA.withCurve(Curve.secp256k1)
    ecdsa2.fromPEM(publicKeyPEM, Key.publicKey)
    const convertedPublicKeyDER = ecdsa2.toDER(Key.publicKey)

    expect(convertedPublicKeyDER).toEqual(originalPublicKeyDER)
  })

  test("correctly imports hex encoded private key", () => {
    ecdsa.genKeyPair()
    const importedECDSA = ECDSA.withCurve(Curve.secp256k1).keyFromPrivate(ecdsa.privateKey)
    expect(importedECDSA.privateKey).toEqual(ecdsa.privateKey)
  })

  test("correctly imports hex encoded public key", () => {
    ecdsa.genKeyPair()
    const importedECDSA = ECDSA.withCurve(Curve.secp256k1).keyFromPublic(ecdsa.publicKey)
    expect(importedECDSA.publicKey).toEqual(ecdsa.publicKey)
  })
})