import * as crypto from "crypto"
import {ED_CURVE, ED_CURVE_TO_DER_MARKER, Key} from "./constants"
import {ISigner, SignatureEncoding, SignatureResponse} from "./types"

export class EdDSA implements ISigner {
  private curve: ED_CURVE
  private _privateKey: crypto.KeyObject
  private _publicKey: crypto.KeyObject
  private readonly privateKeyPrefix
  private readonly publicKeyPrefix

  constructor(curve: ED_CURVE) {
    if(!curve) {
      throw new Error("Curve is required.")
    }
    if (!Object.values(ED_CURVE).includes(curve)) {
      throw new Error(`Unsupported curve: ${curve}.`)
    }

    this.curve = curve
    this.privateKeyPrefix = ED_CURVE_TO_DER_MARKER[curve][Key.privateKey]
    this.publicKeyPrefix = ED_CURVE_TO_DER_MARKER[curve][Key.publicKey]
  }

  static withCurve(curve: ED_CURVE): EdDSA {
    return new EdDSA(curve)
  }

  public get privateKey(): string {
    return this._privateKey.export({
      format: "der",
      type: "pkcs8",
    }).toString("hex").replace(this.privateKeyPrefix, "")
  }

  public get publicKey(): string {
    return this.export("der", Key.publicKey).toString("hex").replace(this.publicKeyPrefix, "")
  }
  private export(format: crypto.KeyFormat, key: Key = Key.privateKey): Buffer {
    if (key == Key.privateKey) {
      return this._privateKey.export({
        format:format as any,
        type: "pkcs8",
      }) as Buffer
    }
    return this._publicKey.export({
      format:format as any,
      type: "spki",
    }) as Buffer
  }

  private import(keyData: string | Buffer, format:crypto.KeyFormat, key: Key)  {
    this.checkPrivateKeyNotAlreadyImported()

    if (key == Key.privateKey) {
      this._privateKey = crypto.createPrivateKey({
        key: keyData,
        format,
        type: "pkcs8",
      })
      this._publicKey = crypto.createPublicKey(this._privateKey)
    } else {
      this._publicKey =  crypto.createPublicKey({
        key: keyData,
        format,
        type: "spki",
      })
    }

  }

  public fromDER(der: string, key: Key = Key.privateKey): EdDSA {
    this.import(Buffer.from(der, "base64"),"der", key)
    return this
  }

  public fromPEM(pem: string, key: Key = Key.privateKey): EdDSA {
    this.import(pem, "pem", key)
    return this
  }

  public toDER(key: Key = Key.privateKey): string {
    this.validateKeyExists(key)
    const keyToEncode = key == Key.privateKey ? this.privateKey : this.publicKey
    return this._encodeDER(keyToEncode, key).toString("base64")
  }

  public toPEM(key: Key = Key.privateKey): string {
    this.validateKeyExists(key)

    return this._encodePEM(this.toDER(key), key)
  }

  sign(
    msg: string | Buffer,
    enc: SignatureEncoding = "object"
  ): SignatureResponse {
    this.validateKeyExists(Key.privateKey)

    const signature = crypto.sign(
      null,
      Buffer.isBuffer(msg) ? msg : Buffer.from(msg, "hex"),
      this._privateKey
    )
    if (enc === "hex") return signature.toString("hex")
    if (enc === "buffer") return signature

    const [r, s] = signature.toString("hex").match(/.{1,64}/g) as string[]
    return {r, s}
  }

  verify(msg: string, signature: SignatureResponse): boolean {
    this.validateKeyExists(Key.publicKey)

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

  keyFromPrivate(privateKey: string | Buffer, enc: crypto.BinaryToTextEncoding): EdDSA {
    const serializedKey = Buffer.isBuffer(privateKey) ? privateKey : Buffer.from(privateKey, enc)
    this._privateKey = crypto.createPrivateKey({
      key: this._encodeDER(serializedKey.toString("hex"), Key.privateKey),
      format: "der",
      type: "pkcs8",
    })
    this._publicKey = crypto.createPublicKey(this._privateKey)
    return this
  }

  keyFromPublic(publicKey: string | Buffer, enc: crypto.BinaryToTextEncoding = "hex"): EdDSA {
    if (this._privateKey) throw new Error("Cannot import public key when private key is set")

    const serializedKey = Buffer.isBuffer(publicKey) ? publicKey : Buffer.from(publicKey, enc)
    this._publicKey = crypto.createPublicKey({
      key: this._encodeDER(serializedKey.toString("hex"), Key.publicKey),
      format: "der",
      type: "spki",
    })
    return this
  }

  genKeyPair(): EdDSA {
    const keypair = crypto.generateKeyPairSync(this.curve as any)
    this._privateKey = keypair.privateKey
    this._publicKey = keypair.publicKey
    return this
  }

  private validateKeyExists(key: Key) {
    if (key == Key.privateKey && !this._privateKey)
      throw new Error("No private key set")
    if (key == Key.publicKey && !this._publicKey)
      throw new Error("No public key set")
  }

  private _encodePEM(keyDer: string, key): string {
    if (key == Key.privateKey)
      return `-----BEGIN PRIVATE KEY-----\n${keyDer}\n-----END PRIVATE KEY-----`

    return `-----BEGIN PUBLIC KEY-----\n${keyDer}\n-----END PUBLIC KEY-----`
  }

  private _encodeDER(hex: string, key): Buffer {
    const prefix = key == Key.privateKey ? this.privateKeyPrefix : this.publicKeyPrefix
    return Buffer.concat([
      Buffer.from(prefix, "hex"),
      Buffer.from(hex, "hex"),
    ])
  }
  private checkPrivateKeyNotAlreadyImported(): void {
    if (this._privateKey) throw new Error("Private key already imported")
  }
}

export default EdDSA
