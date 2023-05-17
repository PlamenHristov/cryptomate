export enum EC_CURVE {
  brainpoolP160r1 = "brainpoolP160r1",
  brainpoolP192r1 = "brainpoolP192r1",
  brainpoolP224r1 = "brainpoolP224r1",
  brainpoolP256r1 = "brainpoolP256r1",
  brainpoolP320r1 = "brainpoolP320r1",
  brainpoolP384r1 = "brainpoolP384r1",
  brainpoolP512r1 = "brainpoolP512r1",
  prime192v1 = "prime192v1",
  prime192v2 = "prime192v2",
  prime192v3 = "prime192v3",
  prime239v1 = "prime239v1",
  prime239v2 = "prime239v2",
  prime239v3 = "prime239v3",
  prime256v1 = "prime256v1",
  secp112r1 = "secp112r1",
  secp112r2 = "secp112r2",
  secp128r1 = "secp128r1",
  secp128r2 = "secp128r2",
  secp160k1 = "secp160k1",
  secp160r1 = "secp160r1",
  secp160r2 = "secp160r2",
  secp192k1 = "secp192k1",
  secp224k1 = "secp224k1",
  secp224r1 = "secp224r1",
  secp256k1 = "secp256k1",
  secp384r1 = "secp384r1",
  secp521r1 = "secp521r1",
}

export const EC_CURVE_TO_DER_MARKER: Record<EC_CURVE, string> = {
  [EC_CURVE.brainpoolP160r1]: "06092B2403030208010101",
  [EC_CURVE.brainpoolP192r1]: "06092B2403030208010103",
  [EC_CURVE.brainpoolP224r1]: "06092B2403030208010105",
  [EC_CURVE.brainpoolP256r1]: "06092B2403030208010107",
  [EC_CURVE.brainpoolP320r1]: "06092B2403030208010109",
  [EC_CURVE.brainpoolP384r1]: "06092B240303020801010B",
  [EC_CURVE.brainpoolP512r1]: "06092B240303020801010D",
  [EC_CURVE.prime192v1]: "06082A8648CE3D030101",
  [EC_CURVE.prime192v2]: "06082A8648CE3D030102",
  [EC_CURVE.prime192v3]: "06082A8648CE3D030103",
  [EC_CURVE.prime239v1]: "06082A8648CE3D030104",
  [EC_CURVE.prime239v2]: "06082A8648CE3D030105",
  [EC_CURVE.prime239v3]: "06082A8648CE3D030106",
  [EC_CURVE.prime256v1]: "06082A8648CE3D030107",
  [EC_CURVE.secp112r1]: "06052B81040006",
  [EC_CURVE.secp112r2]: "06052B81040007",
  [EC_CURVE.secp128r1]: "06052B8104001C",
  [EC_CURVE.secp128r2]: "06052B8104001D",
  [EC_CURVE.secp160k1]: "06052B81040009",
  [EC_CURVE.secp160r1]: "06052B8104001E",
  [EC_CURVE.secp160r2]: "06052B81040021",
  [EC_CURVE.secp192k1]: "06052B8104001F",
  [EC_CURVE.secp224k1]: "06052B81040020",
  [EC_CURVE.secp224r1]: "06052B81040021",
  [EC_CURVE.secp256k1]: "06052B8104000A",
  [EC_CURVE.secp384r1]: "06052B81040022",
  [EC_CURVE.secp521r1]: "06052B81040023",
}

export enum ED_CURVE {
  ed25519 = "ed25519",
  ed488 = "ed488",
}

export const Curve = {... ED_CURVE, ...EC_CURVE}

export enum Key {
  publicKey = "publicKey",
  privateKey = "privateKey",
}

export const ED_CURVE_TO_DER_MARKER: Record<ED_CURVE, Record<Key, string>> = {
  [ED_CURVE.ed25519]: {
    [Key.privateKey]: "302e020100300506032b657004220420",
    [Key.publicKey]: "302a300506032b6570032100",
  },
  [ED_CURVE.ed488]: {
    [Key.privateKey]: "3046020100300506032b6571043b0438",
    [Key.publicKey]: "3042300506032b6571033b00",
  },
}
