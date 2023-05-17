import * as crypto from "crypto"
import { ECDSA } from "../src"
import { EC_CURVE_TO_DER_MARKER } from "../src/constants"

describe("ECDSA", () => {
  let ecdsa
  let validCurve

  beforeAll(() => {
    // Get the first available curve as a valid curve
    validCurve = crypto.getCurves()[0]
  })

  beforeEach(() => {
    ecdsa = new ECDSA(validCurve)
  })

  it("should throw an error for an unsupported curve", () => {
    expect(() => new ECDSA("invalidCurve" as any)).toThrow(
      "Unsupported curve: invalidCurve."
    )
  })

  it("should convert hex data to DER", () => {
    const der = ecdsa.toDER("abcd", true)
    expect(der).toEqual(
      Buffer.concat([
        Buffer.from(EC_CURVE_TO_DER_MARKER[validCurve], "hex"),
        Buffer.from("abcd", "hex"),
      ])
    )
  })

  it("should convert hex data to PEM", () => {
    const pem = ecdsa.toPEM("abcd")
    expect(pem).toMatch(/^-----BEGIN PUBLIC KEY-----/)
    expect(pem).toMatch(/-----END EC PRIVATE KEY-----$/)
  })

  it("should sign and verify a message", () => {
    const keypair = crypto.generateKeyPairSync("ec", {
      namedCurve: validCurve,
    })

    ecdsa.fromPEM(keypair.privateKey.export({ format: "pem", type: "pkcs8" }))

    const msg = "Hello, world!"
    const signature = ecdsa.sign(msg)

    ecdsa.keyFromPublic(
      keypair.publicKey.export({ format: "pem", type: "spki" }),
      "base64"
    )
    const isValid = ecdsa.verify(msg, signature)

    expect(isValid).toBe(true)
  })

  it("should generate a key pair", () => {
    ecdsa.genKeyPair()
    expect(ecdsa._privateKey).toBeTruthy()
    expect(ecdsa._publicKey).toBeTruthy()
  })
})
