export type SignatureEncoding = "hex" | "object" | "buffer";
export type SignatureResponse = string | Buffer | { r: string; s: string };

export interface ISigner {
    sign: (msg: string, enc: SignatureEncoding) => SignatureResponse;
    verify: (msg: string, signature: SignatureResponse) => boolean;
}
