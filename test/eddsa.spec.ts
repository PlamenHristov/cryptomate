import {Curve, ED_CURVE, ED_CURVE_TO_DER_MARKER, EdDSA, Key} from "../src"

describe("EdDSA", () => {
  let eddsa

  beforeEach(() => {
    eddsa = EdDSA.withCurve(Curve.ed25519)
  })

  test("throws an error for an unsupported curve", () => {
    expect(() => new EdDSA("unsupportedCurve" as ED_CURVE)).toThrow("Unsupported curve: unsupportedCurve.")
  })

  test("sign and verify a message", () => {
    const msg = "Hello, World!"
    const signature = eddsa.genKeyPair().sign(msg)
    if (typeof signature === "object") {
      expect(eddsa.verify(msg, signature)).toBe(true)
    }
  })

  test("sign and verify messages with Ed25519 - Test 1", () => {
    const privKey = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    const pubKey = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    const message = ""
    const expectedSignature = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"

    const eddsa = EdDSA.withCurve(Curve.ed25519).keyFromPrivate(privKey, "hex")
    const signature = eddsa.sign(message, "hex")

    expect(signature).toEqual(expectedSignature)
    expect(pubKey).toEqual(eddsa.publicKey)
    expect(privKey).toEqual(eddsa.privateKey)

    EdDSA.withCurve(Curve.ed25519).keyFromPublic(pubKey, "hex")
    const verifyResult = eddsa.verify(message, signature)

    expect(verifyResult).toBe(true)
  })

  test("sign and verify messages with Ed25519 - Test 2", () => {

    const privKey = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
    const pubKey = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    const message = "72"
    const expectedSignature = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    let eddsa = EdDSA.withCurve(Curve.ed25519).keyFromPrivate(privKey, "hex")

    const signature = eddsa.sign(message, "hex")
    expect(signature).toEqual(expectedSignature)
    expect(pubKey).toEqual(eddsa.publicKey)
    expect(privKey).toEqual(eddsa.privateKey)

    eddsa = EdDSA.withCurve(Curve.ed25519).keyFromPublic(pubKey)
    const verifyResult = eddsa.verify(message, signature)

    expect(verifyResult).toBe(true)
  })

  test("converts a private key from and to PEM", () => {
    const eddsa = EdDSA.withCurve(Curve.ed25519).genKeyPair()
    const pemPrivateKey = eddsa.toPEM(Key.privateKey)
    expect(pemPrivateKey).toContain("BEGIN PRIVATE KEY")
    expect(pemPrivateKey).toContain("END PRIVATE KEY")

    const importedKey = EdDSA.withCurve(Curve.ed25519).fromPEM(pemPrivateKey, Key.privateKey).privateKey
    expect(eddsa.privateKey).toEqual(importedKey)
  })

  test("converts a public key from and to PEM", () => {
    const eddsa = EdDSA.withCurve(Curve.ed25519).genKeyPair()
    const pemPrivateKey = eddsa.toPEM(Key.publicKey)
    expect(pemPrivateKey).toContain("BEGIN PUBLIC KEY")
    expect(pemPrivateKey).toContain("END PUBLIC KEY")

    const importedKey = EdDSA.withCurve(Curve.ed25519).fromPEM(pemPrivateKey, Key.publicKey).publicKey
    expect(eddsa.publicKey).toEqual(importedKey)
  })


  test("converts a private key from and to DER", () => {
    const eddsa = EdDSA.withCurve(Curve.ed25519).genKeyPair()
    const derPrivateKey = eddsa.toDER(Key.privateKey)
    expect(derPrivateKey).not.toContain("BEGIN PRIVATE KEY")
    expect(derPrivateKey).not.toContain("END PRIVATE KEY")

    expect(eddsa.privateKey).toEqual(EdDSA.withCurve(Curve.ed25519).fromDER(derPrivateKey, Key.privateKey).privateKey)
  })
  
  test("converts a public key from and to DER", () => {
    const eddsa = EdDSA.withCurve(Curve.ed25519).genKeyPair()
    const derPrivateKey = eddsa.toDER(Key.publicKey)
    expect(derPrivateKey).not.toContain("BEGIN PRIVATE KEY")
    expect(derPrivateKey).not.toContain("END PRIVATE KEY")

    expect(eddsa.publicKey).toEqual(EdDSA.withCurve(Curve.ed25519).fromDER(derPrivateKey,Key.publicKey).publicKey)
  })
  
  test("correctly sets prefix based on curve", () => {
    expect(eddsa.privateKeyPrefix).toBe(ED_CURVE_TO_DER_MARKER[Curve.ed25519][Key.privateKey])
    expect(eddsa.publicKeyPrefix).toBe(ED_CURVE_TO_DER_MARKER[Curve.ed25519][Key.publicKey])
  })

  test("throws an error when signing without a private key", () => {
    const msg = "Hello, World!"
    expect(() => eddsa.sign(msg)).toThrow("No private key set")
  })
})
