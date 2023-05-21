import { Key } from "./enums"
import { BinaryToTextEncoding }  from "crypto"

export type SignatureEncoding = "hex" | "buffer" | "object";
export type SignatureObject = { r: string; s: string };
export type SignatureType = string | Buffer | SignatureObject;
export type SignatureResponse = { "hex": string; "buffer": Buffer; "object": SignatureObject; };
export type KeyEncoding = "pem" | "der";
export type EncodingResponse = { "der": Buffer, "pem": string }

export interface ISigner {
    sign: <T extends SignatureEncoding>(msg: string, enc: T) => SignatureResponse[T];
    verify: (msg: string, signature: SignatureType) => boolean;
}

export interface IKey<T> {
    toDER: (key: Key) => Buffer;
    fromDER: (data : string | Buffer, key: Key) => T;
    toPEM: (key: Key) => string;
    fromPEM: (data: string, key: Key) => T;
    keyFromPrivate(privateKey: string | Buffer, enc: BinaryToTextEncoding): T;
    keyFromPublic(publicKey: string | Buffer, enc: BinaryToTextEncoding): T ;
    genKeyPair(): T;
}