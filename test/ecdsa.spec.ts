import * as crypto from "crypto"
import {ECDSA, Key, EC_CURVE} from "../src"

describe("ECDSA", () => {

  test("all EC curves without ignored ones are supported", () => {
    // missing OID in nodejs
    const ignoredCurves = ["Oakley-EC2N-3", "Oakley-EC2N-4"]
    expect(crypto.getCurves().filter(curve => !ignoredCurves.includes(curve))).toEqual(Object.values(EC_CURVE))
  })

  Object.values(EC_CURVE).forEach((curve: EC_CURVE) => {
    let ecdsa

    beforeEach(() => {
      ecdsa = new ECDSA(curve)
    })

    test(`${curve} throws error for unsupported curve`, () => {
      expect(() => new ECDSA("unsupportedCurve" as EC_CURVE)).toThrow("Unsupported curve: unsupportedCurve.")
    })

    test(`${curve} generate key pair`, () => {
      ecdsa.genKeyPair()

      expect(ecdsa.privateKey).toBeDefined()
      expect(ecdsa.publicKey).toBeDefined()
    })

    test(`${curve} exports private key to DER format`, () => {
      ecdsa.genKeyPair()

      const privateKeyDER = ecdsa.toDER(Key.privateKey)

      expect(privateKeyDER).toBeDefined()
      expect(typeof privateKeyDER).toEqual("object")
    })

    test(`${curve} exports private key to PEM format`, () => {
      ecdsa.genKeyPair()
      const privateKeyPEM = ecdsa.toPEM(Key.privateKey)

      expect(privateKeyPEM).toBeDefined()
      expect(typeof privateKeyPEM).toEqual("string")
    })

    test(`${curve}  sign message`, () => {
      ecdsa.genKeyPair()
      const message = "test message"
      const signature = ecdsa.sign(message)

      expect(signature).toBeDefined()
    })

    test(`${curve} verifies signature`, () => {
      ecdsa.genKeyPair()
      const message = "test message"
      const signature = ecdsa.sign(message)

      expect(ecdsa.verify(message, signature)).toBeTruthy()
    })

    test(`${curve} verify works with public key only`, () => {
      ecdsa.genKeyPair()

      const message = "test message"
      const signature = ecdsa.sign(message)
      const ecdsa2 = ECDSA.withCurve(curve).keyFromPublic(ecdsa.publicKey)

      expect(ecdsa2.verify(message, signature)).toBeTruthy()
    })


    test(`${curve} throws error when private key is not set for signing`, () => {
      const ecdsa = new ECDSA(curve)
      const message = "test message"

      expect(() => ecdsa.sign(message)).toThrow("No private key set")
    })

    test(`${curve} throws error when public key is not set for verification`, () => {
      const ecdsa = new ECDSA(curve)
      const message = "test message"
      const signature = "test signature"

      expect(() => ecdsa.verify(message, signature)).toThrow("No public key set")
    })

    test(`${curve} converts correctly from PEM to DER and back to PEM for private key`, () => {
      ecdsa.genKeyPair()

      const originalPrivateKeyPEM = ecdsa.toPEM(Key.privateKey)
      const ecdsa2 = ECDSA.withCurve(curve).fromDER(ecdsa.toDER(Key.privateKey), Key.privateKey)

      expect(ecdsa2.toPEM(Key.privateKey)).toEqual(originalPrivateKeyPEM)
    })

    test(`${curve} converts correctly from DER to PEM and back to DER for private key`, () => {
      ecdsa.genKeyPair()

      const ecdsa2 = ECDSA.withCurve(curve).fromPEM(ecdsa.toPEM(Key.privateKey), Key.privateKey)

      expect(ecdsa2.toDER(Key.privateKey)).toEqual(ecdsa.toDER(Key.privateKey))
    })

    test(`${curve} converts correctly from PEM to DER and back to PEM for public key`, () => {
      ecdsa.genKeyPair()

      const ecdsa2 = ECDSA.withCurve(curve).fromDER(ecdsa.toDER(Key.publicKey), Key.publicKey)

      expect(ecdsa2.toPEM(Key.publicKey)).toEqual(ecdsa.toPEM(Key.publicKey))
    })

    test(`${curve} converts correctly from DER to PEM and back to DER for public key`, () => {
      ecdsa.genKeyPair()

      const ecdsa2 = ECDSA.withCurve(curve).fromPEM(ecdsa.toPEM(Key.publicKey), Key.publicKey)

      expect(ecdsa2.toDER(Key.publicKey).toString("hex")).toEqual(ecdsa.toDER(Key.publicKey).toString("hex"))
    })

    test(`${curve} correctly imports hex encoded private key`, () => {
      ecdsa.genKeyPair()
      const importedECDSA = ECDSA.withCurve(curve).keyFromPrivate(ecdsa.privateKey)

      expect(importedECDSA.privateKey).toEqual(ecdsa.privateKey)
    })

    test(`${curve} correctly imports hex encoded public key`, () => {
      ecdsa.genKeyPair()

      const importedECDSA = ECDSA.withCurve(curve).keyFromPublic(ecdsa.publicKey)

      expect(importedECDSA.publicKey).toEqual(ecdsa.publicKey)
    })
  })
})
