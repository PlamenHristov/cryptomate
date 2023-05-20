import * as crypto from "crypto"
import { EC_CURVE, EC_CURVE_TO_DER_MARKER, EC_CURVE_TO_OID, Key } from "./constants"
import { ISigner, SignatureEncoding, SignatureResponse } from "./types"

export class ECDSA implements ISigner {
  private readonly EC_PUBLIC_KEY_OID = "06072a8648ce3d0201"
  private readonly ECDSA_OID_PREFIX = "020100301"
  private readonly ECDSA_OID_SUFFIX = "02010104"
  private readonly ecdh: crypto.ECDH
  private readonly privateKeyPrefix: string
  private readonly publicKeyPrefix: string
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
    this.privateKeyPrefix = EC_CURVE_TO_DER_MARKER[curve][Key.privateKey][0]
    this.publicKeyPrefix = EC_CURVE_TO_DER_MARKER[curve][Key.publicKey][0]
  }

  static withCurve(curve: EC_CURVE): ECDSA {
    return new ECDSA(curve)
  }

  public get privateKey(): string {
    const pkcs8Hex = this._privateKey.export({
      format: "der",
      type: "pkcs8",
    }).toString("hex")
    const privateKeyLengthSizeIndex = pkcs8Hex.indexOf(this.ECDSA_OID_SUFFIX) + this.ECDSA_OID_SUFFIX.length
    const privateKeyLengthSizeIndexEnd = privateKeyLengthSizeIndex + 2
    const privateKeySize = pkcs8Hex.substring(privateKeyLengthSizeIndex, privateKeyLengthSizeIndexEnd)
    const privateKeyEnd = privateKeyLengthSizeIndexEnd + (parseInt(privateKeySize, 16) * 2)
    return pkcs8Hex.substring(privateKeyLengthSizeIndexEnd, privateKeyEnd)
  }

  public get publicKey(): string {
    return this.export("der", Key.publicKey)
      .toString("hex")
      .replace(this.EC_PUBLIC_KEY_OID, "")
      .replace(this.oid, "")
      .substring(12)
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
    if(key == Key.publicKey)
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
      this._privateKey
    )

    const parsedSignature = this._DERtoRS(signature)
    if (enc === "hex") return parsedSignature
    if (enc === "buffer") return Buffer.from(parsedSignature)
    if (enc === "object") {
      return {
        r: parsedSignature.substring(0, 64),
        s: parsedSignature.substring(64, 128)
      }
    }

    throw new Error(`Unsupported encoding: ${enc}`)
  }

  verify(msg: string, signature: SignatureResponse): boolean {
    this.validateKeyExists(Key.publicKey)
    const derSignature = this._RStoDER(this._castSignature(signature))

    return crypto.verify(
      null,
      Buffer.from(msg, "hex"),
      this._publicKey,
      derSignature
    )
  }

  private _castSignature(signature: string | Buffer | { r: string; s: string }): string {
    if (Buffer.isBuffer(signature)) {
      signature = signature.toString("hex")
    } else if (typeof signature === "object") {
      signature = signature.r + signature.s
    }
    if (!this._publicKey) throw new Error("No public key set")
    return signature
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
    // const encodedPublicKey = '03' + (publicKeyHex.length / 2).toString(16) + '00' + publicKeyHex;
    const encodedPublicKey = "03" + (publicKeyHex.length / 2).toString(16) + publicKeyHex
    const algorithmIdentifier = "30" + ((this.EC_PUBLIC_KEY_OID.length + this.oid.length) / 2).toString(16) + this.EC_PUBLIC_KEY_OID + this.oid
    const totalLength = ((algorithmIdentifier.length + encodedPublicKey.length) / 2).toString(16).padStart(2, "0")
    const derPublicKey = "30" + totalLength + algorithmIdentifier + encodedPublicKey
    return Buffer.from(derPublicKey, "hex")
  }

  private checkPrivateKeyNotAlreadyImported(): void {
    if (this._privateKey) throw new Error("Private key already imported")
  }

  private _DERtoRS(signature: string | Buffer): string {
    const sigBuf = !Buffer.isBuffer(signature) ? Buffer.from(signature, "hex") : signature
    if (!Buffer.isBuffer(sigBuf)) {
      throw new Error("Invalid input type. Expected Buffer or hex string")
    }

    if (sigBuf[0] !== 0x30 || sigBuf[2] !== 0x02) {
      throw new Error("Invalid DER signature")
    }
    const DER_START_OFFSET = 4
    const DER_R_OFFSET = 2
    const lenR = sigBuf[3]
    const startS = lenR + DER_START_OFFSET
    const lenS = sigBuf[startS + 1]
    const startR = startS + DER_R_OFFSET
    const startSig = startR + lenS

    if (startSig !== signature.length) {
      throw new Error("Invalid DER signature length")
    }
    let r = sigBuf.subarray(DER_START_OFFSET, startS).toString("hex").padStart(64, "0")
    let s = sigBuf.subarray(startR, startSig).toString("hex").padStart(64, "0")

    // positive integers with most significant bit set must be prefixed with a zero in ASN.1 encoding
    while (r.length > 64) {
      r = r.slice(1)
    }
    while (s.length > 64) {
      s = s.slice(1)
    }
    return `${r}${s}`
  }

  private _RStoDER(signature: string | Buffer): Buffer {
    if (typeof signature !== "string" || signature.length !== 128) {
      throw new Error("Invalid r||s signature format")
    }

    let r = Buffer.from(signature.slice(0, 64), "hex")
    let s = Buffer.from(signature.slice(64, 128), "hex")

    // Add leading zero to r and s if their highest bit is 1
    if (r[0] >= 0x80) r = Buffer.concat([Buffer.from([0x00]), r])
    if (s[0] >= 0x80) s = Buffer.concat([Buffer.from([0x00]), s])

    const rDer = Buffer.concat([Buffer.from([0x02, r.length]), r])
    const sDer = Buffer.concat([Buffer.from([0x02, s.length]), s])
    return Buffer.concat([Buffer.from([0x30, rDer.length + sDer.length]), rDer, sDer])
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
      key: publicKey,
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

  private _derEncodePrivateKey(privateKeyHex: string): Buffer {
    const publicKeyHex = `04${this.publicKey}`
    const keyHexLength = (privateKeyHex.length / 2).toString(16).padStart(2, "0")
    const publicKeyLength = (publicKeyHex.length / 2).toString(16).padStart(2, "0")

    const encodedPrivateKey = "04" + keyHexLength + privateKeyHex
    const encodedPublicKey = "03" + publicKeyLength + "00" + publicKeyHex  // ASN.1 BitString
    const encodedOid = "06" + (this.oid.length / 2).toString(16) + this.oid

    const encodedAlgorithmIdentifier = this.EC_PUBLIC_KEY_OID + "a0" + encodedOid

    // ASN.1 DER encoding for PKCS#8 private key is:
    // 0x30 + len(total) + version (020100) + AlgorithmIdentifier + Octet String + private key + Bit String + public key
    const totalLength = (2 + 3 + encodedAlgorithmIdentifier.length / 2 + 2 + encodedPrivateKey.length / 2 + 2 + encodedPublicKey.length / 2).toString(16).padStart(2, "0")
    const derPk = "30" + totalLength + "020100" + encodedAlgorithmIdentifier + encodedPrivateKey + encodedPublicKey
    return Buffer.from(derPk, "hex")
  }
}
