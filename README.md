# cryptomate

Ergonomic, zero-dependency crypto module wrapper for ECDSA and EdDSA signatures.

[![Pull Request Checks](https://github.com/PlamenHristov/cryptomate/actions/workflows/pr.yml/badge.svg?branch=main&event=release)](https://github.com/PlamenHristov/cryptomate/actions/workflows/pr.yml)
[![Coverage Status](https://coveralls.io/repos/github/PlamenHristov/cryptomate/badge.svg?branch=main)](https://coveralls.io/github/PlamenHristov/cryptomate?branch=main)
[![Known Vulnerabilities](https://snyk.io/test/github/PlamenHristov/cryptomate/badge.svg?targetFile=package.json)](https://snyk.io/test/github/PlamenHristov/cryptomate?targetFile=package.json)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Key features of the module include:

- Generation of ECDSA and EdDSA key pairs.
- Conversion between PEM (Privacy-Enhanced Mail) and DER (Distinguished Encoding Rules) formats.
- Extraction of public key from a given private key.
- Message signing and verification using ECDSA and EdDSA algorithms.

## Installation

To install `cryptomate`, use the following npm command:

```bash
npm i --save cryptomate
```

## Quick Start

Here is an example demonstrating the use of the ECDSA functionality provided by this module:

```javascript
const {ECDSA, EC_CURVE, Key, SignatureEncoding} = require('cryptomate');

// Generate an ECDSA key pair.
const ecdsa = ECDSA.withCurve(EC_CURVE.secp256k1).genKeyPair();

// Sign a message.
let message = "Hello, World!";
let signature = ecdsa.sign(message, SignatureEncoding.HEX);

// Verify the signature.
console.log(ecdsa.verify(message, signature)); // Outputs: true

// Export keys in PEM format.
let privateKeyPEM = ecdsa.toPEM(Key.privateKey);
let publicKeyPEM = ecdsa.toPEM(Key.publicKey);

// Import keys from PEM format.
let importedECDSA = ECDSA.withCurve(EC_CURVE.secp256k1).fromPEM(privateKeyPEM, Key.privateKey);

```

## API Reference

### ECDSA

#### ECDSA.withCurve(curve)

A factory method to construct an ECDSA object with a given elliptic curve.

##### Parameters

- `curve` - The elliptic curve to use. This can be one of the following values:
    - `EC_CURVE.P_256` - NIST P-256 curve.
    - `EC_CURVE.P_384` - NIST P-384 curve.
    - `EC_CURVE.P_521` - NIST P-521 curve.
    - `EC_CURVE.SECP256K1` - SECP256K1 curve.
    - `EC_CURVE.SECP256R1` - SECP256R1 curve.
    - `EC_CURVE.SECP384R1` - SECP384R1 curve.
    - `EC_CURVE.SECP521R1` - SECP521R1 curve.
    - ...

##### Returns

An ECDSA object with the given elliptic curve.

#### ECDSA.genKeyPair()

Generates a new ECDSA key pair.

##### Returns

An ECDSA object with a newly generated key pair.

#### ECDSA.fromPEM(pem, keyType)

Constructs an ECDSA object from a given PEM string.

##### Parameters

- `pem` - The PEM string to construct the ECDSA object from.
- `keyType` - The type of key to construct. This can be one of the following values:
    - `Key.privateKey` - Private key.
    - `Key.publicKey` - Public key.

##### Returns

An ECDSA object with the given PEM string.

#### ECDSA.toPEM(keyType)

Converts the ECDSA object to a PEM string.

##### Parameters

- `keyType` - The type of key to convert. This can be one of the following values:
    - `Key.privateKey` - Private key.
    - `Key.publicKey` - Public key.

##### Returns

A PEM string representing the ECDSA object.

#### ECDSA.getPublicKey()

Extracts the public key from the ECDSA object.

##### Returns

A Buffer object containing the public key.

#### ECDSA.sign(message, encoding)

Signs a message using the ECDSA object.

##### Parameters

- `message` - The message to sign.
- `encoding` - The encoding of the message. This can be one of the following values:
    - `SignatureEncoding.HEX` - The message is encoded in hexadecimal format.
    - `SignatureEncoding.BASE64` - The message is encoded in Base64 format.
    - `SignatureEncoding.UTF8` - The message is encoded in UTF-8 format.
    - ...

##### Returns

A Buffer object containing the signature.

#### ECDSA.verify(message, signature, encoding)

Verifies a signature using the ECDSA object.

##### Parameters

- `message` - The message to verify.
- `signature` - The signature to verify.
- `encoding` - The encoding of the message. This can be one of the following values:
    - `SignatureEncoding.HEX` - The message is encoded in hexadecimal format.
    - `SignatureEncoding.BASE64` - The message is encoded in Base64 format.
    - `SignatureEncoding.UTF8` - The message is encoded in UTF-8 format.
    - ...

##### Returns

A boolean value indicating whether the signature is valid.

### EdDSA

Please note that the EdDSA class shares similar method names and functionalities to the ECDSA class for key pair
generation,
signing and verifying messages, and importing/exporting keys in various formats.
Refer to the ECDSA API documentation provided above for further details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
