type hexNumber = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9;
type hexLetter = "A" | "B" | "C" | "D" | "E" | "F";
// type hexAlphabet = hexLetter | hexNumber;

type TypeRange<
  N extends number,
  Acc extends Array<number> = []
> = Acc["length"] extends N ? Acc : TypeRange<N, [...Acc, Acc["length"]]>;
// type NumberRange = TypeRange<9>[number];

export type SignatureEncoding = "hex" | "object" | "buffer";
export type SignatureResponse = string | Buffer | { r: string; s: string };
// export type SignFunction = (msg: SignatureResponse) => SignatureResponse;


export interface ISigner {
    sign: (msg: string, enc: SignatureEncoding) => SignatureResponse;
    verify: (msg: string, signature: SignatureResponse) => boolean;
}
export type ED_TYPES = "ed25519" | "ed448";
