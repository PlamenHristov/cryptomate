export type SignatureEncoding = "hex" | "buffer" | "object";
export type SignatureObject = { r: string; s: string };
export type SignatureType = string | Buffer | SignatureObject;
export type SignatureResponse = { "hex": string; "buffer": Buffer; "object": SignatureObject; };

export interface ISigner {
    sign: <T extends SignatureEncoding>(msg: string, enc: T) => SignatureResponse[T];
    verify: (msg: string, signature: SignatureType) => boolean;
}
