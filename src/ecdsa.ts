import * as crypto from "crypto"
import { EC_CURVE, EC_CURVE_TO_DER_MARKER } from "./constants"
import { SignatureEncoding, SignatureResponse } from "./types"

export class ECDSA {
  private curve: EC_CURVE
  private _privateKey: crypto.KeyObject
  private _publicKey: crypto.KeyObject
  private readonly pemPrivateKeyPrefix
  private readonly pemPublicKeyPrefix

  constructor(curve: EC_CURVE) {
    if (!crypto.getCurves().includes(curve)) {
      throw new Error(`Unsupported curve: ${curve}.`)
    }

    this.curve = curve
    this.pemPrivateKeyPrefix = EC_CURVE_TO_DER_MARKER[curve]
  }

  private toDER(hex: string, publicKey: boolean): Buffer {
    return Buffer.concat([
      Buffer.from(this.pemPrivateKeyPrefix, "hex"),
      Buffer.from(hex, "hex"),
    ])
  }

  public toPEM(hexData: string, publickey = true): string {
    if (publickey)
      return `-----BEGIN PUBLIC KEY-----\n${this.toDER(
        hexData,
        publickey
      ).toString("base64")}\n-----END EC PRIVATE KEY-----`

    return `-----BEGIN EC PRIVATE KEY-----\n${this.toDER(
      hexData,
      publickey
    ).toString("base64")}\n-----END PRIVATE KEY-----`
  }

  fromPEM(data: string) {
    this._privateKey = crypto.createPrivateKey({
      key: data,
      format: "pem",
    })
  }

  sign(
    msg: string | Buffer,
    enc: SignatureEncoding = "object"
  ): SignatureResponse {
    const signature = crypto.sign(
      null,
      Buffer.isBuffer(msg) ? msg : Buffer.from(msg, "hex"),
      this._privateKey
    )
    const [r, s] = signature.toString("hex").match(/.{1,64}/g) as string[]
    if (enc === "hex") return signature.toString("hex")
    if (enc === "buffer") return signature
    return { r, s }
  }

  verify(msg: string, signature: SignatureResponse) {
    if (Buffer.isBuffer(signature)) {
      signature = signature.toString("hex")
    } else if (typeof signature === "object") {
      signature = signature.r + signature.s
    }
    if (!this._publicKey) throw new Error("No public key set")

    return crypto.verify(
      null,
      Buffer.from(msg, "hex"),
      this._publicKey,
      Buffer.from(signature, "hex")
    )
  }

  keyFromPrivate(privateKey: string, enc: crypto.BinaryToTextEncoding = "hex") {
    this._privateKey = crypto.createPrivateKey({
      key: this.toPEM(Buffer.from(privateKey, enc).toString("hex")),
      format: "pem",
    })
    this._publicKey = crypto.createPublicKey(this._privateKey)
  }

  keyFromPublic(pub: string, enc: crypto.BinaryToTextEncoding) {
    this._publicKey = crypto.createPublicKey({
      key: this.toPEM(Buffer.from(pub, enc).toString("hex"), true),
      format: "pem",
    })
  }

  genKeyPair() {
    const keypair = crypto.generateKeyPairSync("ec", {
      namedCurve: this.curve,
    })
    this._privateKey = keypair.privateKey
    this._publicKey = keypair.publicKey
  }
}
export default ECDSA
