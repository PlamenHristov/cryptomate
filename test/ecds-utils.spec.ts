import {testVector} from "./_heplers/fixtures"
import {EC_CURVE, ECDSA} from "../src"

describe("ecdsa-utils secp256k1", function () {
  let ecdsa
  beforeEach(() => {
    ecdsa = new ECDSA(EC_CURVE.secp256k1)
  })

  testVector.forEach((pkTestCase, idx) => {
    test(`${idx} converts from compressed to uncompressed and back correctly`, () => {
      ecdsa.keyFromPublic(pkTestCase.publicKeyUncompressed, "hex")
      expect(ecdsa.getPublicKeyCompressed()).toEqual(pkTestCase.publicKeyCompressed)
    })

    test(`${idx} converts from uncompressed to compressed and back correctly`, () => {
      ecdsa.keyFromPublic(pkTestCase.publicKeyCompressed, "hex")
      expect(ecdsa.publicKey).toEqual(pkTestCase.publicKeyUncompressed)
    })
    test(`${idx} `, () => {

    })
  })
})
