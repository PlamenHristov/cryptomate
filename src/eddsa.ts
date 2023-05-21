import * as crypto from "crypto"
import { ED_CURVE_TO_DER_MARKER } from "./constants"
import { ED_CURVE, Key } from "./enums"
import { IKey, ISigner, SignatureEncoding, SignatureResponse, SignatureType } from "./types"

export class EdDSA implements ISigner, IKey<EdDSA> {
  private curve: ED_CURVE
  private _privateKey: crypto.KeyObject
  private _publicKey: crypto.KeyObject
  private readonly privateKeyPrefix: string
  private readonly publicKeyPrefix: string

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

  public fromDER(der: string | Buffer, key: Key = Key.privateKey): EdDSA {
    this.import(Buffer.isBuffer(der) ? der : Buffer.from(der, "hex"),"der", key)
    return this
  }

  public fromPEM(pem: string, key: Key = Key.privateKey): EdDSA {
    this.import(pem, "pem", key)
    return this
  }

  public toDER(key: Key = Key.privateKey): Buffer {
    this.validateKeyExists(key)
    const keyToEncode = key == Key.privateKey ? this.privateKey : this.publicKey
    return this._encodeDER(keyToEncode, key)
  }

  public toPEM(key: Key = Key.privateKey): string {
    this.validateKeyExists(key)

    return this._encodePEM(this.toDER(key), key)
  }

  sign<T extends SignatureEncoding>(msg: string | Buffer, enc?: T): SignatureResponse[T] {
    this.validateKeyExists(Key.privateKey)

    const signature = crypto.sign(
      null,
      Buffer.isBuffer(msg) ? msg : Buffer.from(msg, "hex"),
      { key:this._privateKey , dsaEncoding: "ieee-p1363"}
    )
    if (enc === "hex") return signature.toString("hex") as SignatureResponse[T]
    if (enc === "buffer") return signature as SignatureResponse[T]

    const [r, s] = signature.toString("hex").match(/.{1,64}/g) as string[]
    return {r, s} as SignatureResponse[T]
  }

  verify(msg: string, signature: SignatureType): boolean {
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

  public keyFromPrivate(privateKey: string | Buffer, enc: crypto.BinaryToTextEncoding = "hex"): EdDSA {
    const serializedKey = Buffer.isBuffer(privateKey) ? privateKey : Buffer.from(privateKey, enc)
    this._privateKey = crypto.createPrivateKey({
      key: this._encodeDER(serializedKey.toString("hex"), Key.privateKey),
      format: "der",
      type: "pkcs8",
    })
    this._publicKey = crypto.createPublicKey(this._privateKey)
    return this
  }

  public keyFromPublic(publicKey: string | Buffer, enc: crypto.BinaryToTextEncoding = "hex"): EdDSA {
    if (this._privateKey) throw new Error("Cannot import public key when private key is set")

    const serializedKey = Buffer.isBuffer(publicKey) ? publicKey : Buffer.from(publicKey, enc)
    this._publicKey = crypto.createPublicKey({
      key: this._encodeDER(serializedKey.toString("hex"), Key.publicKey),
      format: "der",
      type: "spki",
    })
    return this
  }

  public genKeyPair(): EdDSA {
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

  private _encodePEM(keyDer: Buffer, key: Key): string {
    if (key == Key.privateKey)
      return `-----BEGIN PRIVATE KEY-----\n${keyDer.toString("base64")}\n-----END PRIVATE KEY-----`

    return `-----BEGIN PUBLIC KEY-----\n${keyDer.toString("base64")}\n-----END PUBLIC KEY-----`
  }

  private _encodeDER(hex: string, key: Key): Buffer {
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
