# App Attest Validator

This repository contains a strict, opt-in cryptographic validator for Apple App Attest assertions. It verifies ECDSA signatures over exact Sig_structure bytes and makes no trust or policy decisions.

## What This Is

- **A math engine, not a product** — Pure cryptographic verification with zero policy logic
- **A reference, not a demo** — Correct implementation that matches Apple's specification
- **A thing Apple should've shipped internally** — Forensic-grade tooling for App Attest debugging

## Architecture

The validator maintains strict separation between:
- **Decoding** — Parsing assertion/attestation objects
- **Reconstruction** — Building Sig_structure CBOR bytes
- **Validation** — Cryptographic signature verification
- **Trust/Policy** — External (not in this tool)

## Components

### CLI Validator
- `AssertionValidator.swift` — Core validation logic
- `AssertionValidationContext.swift` — Explicit input context
- Uses CryptoKit for P-256 ECDSA verification

### Server Validator
- `ServerAssertionValidator.swift` — Platform-agnostic server-side validator
- Accepts raw `Data` inputs (sigStructure, signatureDER, publicKey)
- Pure, stateless, no dependencies beyond Foundation + CryptoKit
- Works on macOS and Linux

## Usage

The validator requires explicit inputs:
- `sigStructure`: CBOR-encoded Sig_structure bytes (from decoder)
- `signatureDER`: ASN.1 DER ECDSA signature bytes
- `publicKey`: Uncompressed P-256 public key (65 bytes: 0x04 || X || Y)

It returns:
- `.verified` — Signature verified
- `.failed(reason:)` — Cryptographic verification failed
- `.cannotValidate(reason:)` — Missing or invalid context

## Single Source of Truth

The validator uses the **exact same** sig_structure bytes that are displayed/decoded. It never reconstructs them. This ensures:
- UI hash == validator hash
- Verification results are mathematically meaningful
- No "close enough" reconstruction errors

## Development

Built and tested on macOS. Deploys to Linux (Orange Pi) with the same code.

The validator never changes. Only the inputs do.
