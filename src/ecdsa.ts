import * as crypto from "crypto"

import {BYTE_LENGTH_IN_HEX, EC_CURVE, EC_CURVE_TO_OID, Key} from "./constants"
import {ISigner, SignatureEncoding, SignatureResponse} from "./types"

export class ECDSA implements ISigner {
  private readonly EC_PUBLIC_KEY_OID = "06072a8648ce3d0201"
  private readonly ECDSA_OID_PREFIX = "02010030"
  private readonly ECDSA_OID_SUFFIX = "020101"
  private readonly PUBLIC_KEY_START_INDICATOR = "00"

  private readonly ecdh: crypto.ECDH
  private readonly oid: string
  private _privateKey: crypto.KeyObject
  private _publicKey: crypto.KeyObject

  constructor(private readonly curve: EC_CURVE) {
    if (!curve) {
      throw new Error("Curve is required.")
    }
    if (!Object.values(EC_CURVE).includes(curve)) {
      throw new Error(`Unsupported curve: ${curve}.`)
    }

    this.ecdh = crypto.createECDH(curve)
    this.oid = EC_CURVE_TO_OID[curve]
  }

  static withCurve(curve: EC_CURVE): ECDSA {
    return new ECDSA(curve)
  }

  public get privateKey(): string {
    const pkcs8Hex = this._privateKey.export({
      format: "der",
      type: "pkcs8",
    }).toString("hex")
    // start of the version number + length of type identifier for the private key
    const privateKeyLengthSizeIndex = pkcs8Hex.indexOf(this.ECDSA_OID_SUFFIX) + this.ECDSA_OID_SUFFIX.length + 2
    const privateKeyLengthSizeIndexEnd = privateKeyLengthSizeIndex + 2
    const privateKeySize = pkcs8Hex.substring(privateKeyLengthSizeIndex, privateKeyLengthSizeIndexEnd)
    const privateKeyEnd = privateKeyLengthSizeIndexEnd + this._decodeOidLength(privateKeySize) * BYTE_LENGTH_IN_HEX
    return pkcs8Hex.substring(privateKeyLengthSizeIndexEnd, privateKeyEnd)
  }

  public get publicKey(): string {
    const pkcs8Hex = this.export("der", Key.publicKey).toString("hex")
    const pkLengthIndexStart = pkcs8Hex.indexOf(this.oid) + this.oid.length + BYTE_LENGTH_IN_HEX

    let pkLengthIndexEnd = pkLengthIndexStart
    while (pkcs8Hex.substring(pkLengthIndexEnd, pkLengthIndexEnd + BYTE_LENGTH_IN_HEX) != this.PUBLIC_KEY_START_INDICATOR) {
      pkLengthIndexEnd += BYTE_LENGTH_IN_HEX
    }

    const publicKeySize = pkcs8Hex.substring(pkLengthIndexStart, pkLengthIndexEnd)
    const publicKeyStart= pkLengthIndexEnd + this.PUBLIC_KEY_START_INDICATOR.length
    const publicKeyEnd = publicKeyStart + (this._decodeOidLength(publicKeySize) * BYTE_LENGTH_IN_HEX)
    return pkcs8Hex.substring(publicKeyStart, publicKeyEnd)
  }

  private export(format: crypto.KeyFormat, key: Key = Key.privateKey): Buffer {
    if (key == Key.privateKey) {
      return this._privateKey.export({
        format: format as any,
        type: "pkcs8",
      }) as Buffer
    }
    return this._publicKey.export({
      format: format as any,
      type: "spki",
    }) as Buffer
  }

  private import(keyData: string | Buffer, format: crypto.KeyFormat, key: Key) {
    this.checkPrivateKeyNotAlreadyImported()

    if (key == Key.privateKey) {
      this._privateKey = crypto.createPrivateKey({
        key: keyData,
        format,
        type: "pkcs8",
      })
      this._publicKey = crypto.createPublicKey(this._privateKey)
    } else {
      this._publicKey = crypto.createPublicKey({
        key: keyData,
        format,
        type: "spki",
      })
    }

  }

  public fromDER(der: string, key: Key = Key.privateKey): ECDSA {
    this.import(Buffer.from(der, "hex"), "der", key)
    return this
  }

  public fromPEM(pem: string, key: Key = Key.privateKey): ECDSA {
    this.import(pem, "pem", key)
    return this
  }

  public toDER(key: Key = Key.privateKey): Buffer {
    this.validateKeyExists(key)
    if (key == Key.publicKey)
      return this._publicKey.export({
        format: "der",
        type: "spki",
      })

    return this._privateKey.export({
      format: "der",
      type: "pkcs8",
    })
  }

  public toPEM(key: Key = Key.privateKey): string {
    this.validateKeyExists(key)

    return this._encodePEM(this.toDER(key).toString("base64"), key)
  }

  sign(
    msg: string | Buffer,
    enc: SignatureEncoding = "object"
  ): SignatureResponse {
    this.validateKeyExists(Key.privateKey)
    const signature = crypto.sign(
      null,
      Buffer.isBuffer(msg) ? msg : Buffer.from(msg, "hex"),
      {
        key: this._privateKey,
        dsaEncoding: "ieee-p1363"
      }
    )

    if (enc === "hex") return signature.toString("hex")
    if (enc === "buffer") return signature
    if (enc === "object")
      return {
        r: signature.subarray(0, signature.length / 2).toString("hex"),
        s: signature.subarray(signature.length / 2, signature.length).toString("hex")
      }

    throw new Error(`Unsupported encoding: ${enc}`)
  }

  verify(msg: string, signature: SignatureResponse): boolean {
    this.validateKeyExists(Key.publicKey)
    const castedSignature = this._castSignature(signature)

    return crypto.verify(
      null,
      Buffer.from(msg, "hex"),
      {
        key: this._publicKey,
        dsaEncoding: "ieee-p1363"
      },
      castedSignature
    )
  }

  private _castSignature(signature: string | Buffer | { r: string; s: string }): Buffer {
    if (Buffer.isBuffer(signature))
      return signature

    if (typeof signature === "object")
      signature = signature.r + signature.s

    if (!this._publicKey) throw new Error("No public key set")
    return Buffer.from(signature, "hex")
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
    return key == Key.privateKey ?
      this._derEncodePrivateKey(hex) :
      this._derEncodePublicKey(hex)
  }

  private _derEncodePublicKey(publicKeyHex: string): Buffer {
    const paddedPublicKeyHex = `${this.PUBLIC_KEY_START_INDICATOR}${publicKeyHex}`
    const encodedPublicKey  = `03${this._encodeOidLength(paddedPublicKeyHex)}${paddedPublicKeyHex}`
    const keyMetadata = `${this.EC_PUBLIC_KEY_OID}${this.oid}`
    const algorithmIdentifier = `30${this._encodeOidLength(keyMetadata)}${keyMetadata}`
    const fullString = `${algorithmIdentifier}${encodedPublicKey}`
    return Buffer.from("30" + this._encodeOidLength(fullString) + fullString, "hex")
  }

  private checkPrivateKeyNotAlreadyImported(): void {
    if (this._privateKey) throw new Error("Private key already imported")
  }

  keyFromPublic(publicKey: string | Buffer, enc: crypto.BinaryToTextEncoding = "hex"): ECDSA {
    if (this._privateKey) throw new Error("Cannot import public key when private key is set")

    const serializedKey = Buffer.isBuffer(publicKey) ? publicKey : Buffer.from(publicKey, enc)
    this._publicKey = crypto.createPublicKey({
      key: this._encodeDER(serializedKey.toString("hex"), Key.publicKey),
      format: "der",
      type: "spki",
    })
    return this
  }

  genKeyPair(): ECDSA {
    const keypair = crypto.generateKeyPairSync("ec", {
      namedCurve: this.curve
    })
    this._privateKey = keypair.privateKey
    this._publicKey = keypair.publicKey
    return this
  }

  keyFromPrivate(privateKey: string | Buffer, enc: crypto.BinaryToTextEncoding = "hex"): ECDSA {
    const serializedKey = Buffer.isBuffer(privateKey) ? privateKey : Buffer.from(privateKey, enc)

    this.ecdh.setPrivateKey(serializedKey)

    const publicKey = this.ecdh.getPublicKey()
    this._publicKey = crypto.createPublicKey({
      key: this._encodeDER(publicKey.toString("hex"), Key.publicKey),
      format: "der",
      type: "spki",
    })

    const derPrivateKey = this._derEncodePrivateKey(serializedKey.toString("hex"))
    this._privateKey = crypto.createPrivateKey({
      key: derPrivateKey,
      format: "der",
      type: "pkcs8",
    })

    return this
  }

  private _decodeOidLength(hexString: string): number {
    const firstByte = parseInt(hexString.slice(0, BYTE_LENGTH_IN_HEX), 16)

    if (firstByte < 128)
      return firstByte

    const byteCount = firstByte - 128
    const lengthBytes = hexString.slice(BYTE_LENGTH_IN_HEX, BYTE_LENGTH_IN_HEX * (byteCount + 1))
    return parseInt(lengthBytes, 16)
  }

  private _encodeOidLength(hexString: string): string {
    const BYTE_LENGTH_IN_HEX = 2
    const length = hexString.length / BYTE_LENGTH_IN_HEX

    if (length < 128)
      return length.toString(16).padStart(BYTE_LENGTH_IN_HEX, "0")

    let lengthBytes = length.toString(16)
    const byteCount = Math.ceil(lengthBytes.length / BYTE_LENGTH_IN_HEX)
    const initialByte = (128 + byteCount).toString(16)
    lengthBytes = lengthBytes.padStart(byteCount * BYTE_LENGTH_IN_HEX, "0")
    return initialByte + lengthBytes
  }

  private _derEncodePrivateKey(privateKeyHex: string): Buffer {
    const publicKeyHex = `${this.PUBLIC_KEY_START_INDICATOR}${this.publicKey}`

    const encodedPublicKey = `03${this._encodeOidLength(publicKeyHex)}${publicKeyHex}`
    const encodedPrivateKey = `04${this._encodeOidLength(privateKeyHex)}${privateKeyHex}`
    const privateKeyAndPublicKey = `${this.ECDSA_OID_SUFFIX}${encodedPrivateKey}A1${this._encodeOidLength(encodedPublicKey)}${encodedPublicKey}`
    let privateKeyAndPublicKeyEncoding = `30${this._encodeOidLength(privateKeyAndPublicKey)}${privateKeyAndPublicKey}`
    privateKeyAndPublicKeyEncoding = `04${this._encodeOidLength(privateKeyAndPublicKeyEncoding)}${privateKeyAndPublicKeyEncoding}`
    const ecMetadata = `${this.EC_PUBLIC_KEY_OID}${this.oid}`
    const fullEncoding = `${this.ECDSA_OID_PREFIX}${this._encodeOidLength(ecMetadata)}${ecMetadata}${privateKeyAndPublicKeyEncoding}`
    const derPk = `30${this._encodeOidLength(fullEncoding)}${fullEncoding}`
    return Buffer.from(derPk, "hex")
  }
}
