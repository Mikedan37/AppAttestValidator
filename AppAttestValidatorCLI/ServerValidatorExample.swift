//
//  ServerValidatorExample.swift
//  AppAttestValidatorCLI
//
//  Created by Michael Danylchuk on 1/15/26.
//
//  Example usage of ServerAssertionValidator.
//  Demonstrates how to use the validator in server contexts (Vapor, CLI, etc.)
//

import Foundation

/// Example usage of the server-side assertion validator.
///
/// This demonstrates:
/// 1. Creating a validation context from raw Data inputs
/// 2. Validating an assertion
/// 3. Handling results appropriately
struct ServerValidatorExample {
    
    /// Example: Validate an assertion with raw Data inputs.
    ///
    /// - Parameters:
    ///   - sigStructure: CBOR-encoded Sig_structure bytes (from decoder)
    ///   - signatureDER: ASN.1 DER ECDSA signature bytes
    ///   - publicKey: Uncompressed P-256 public key (65 bytes: 0x04 || X || Y)
    /// - Returns: Validation result
    static func validateAssertion(
        sigStructure: Data,
        signatureDER: Data,
        publicKey: Data
    ) -> ServerAssertionValidationResult {
        // Create validation context (validates input formats)
        guard let context = ServerAssertionValidationContext.create(
            sigStructure: sigStructure,
            signatureDER: signatureDER,
            publicKey: publicKey
        ) else {
            return .cannotValidate(reason: "Invalid input format: sigStructure or signatureDER empty, or publicKey not 65 bytes uncompressed")
        }
        
        // Perform validation
        return ServerAssertionValidator.validate(context: context)
    }
    
    /// Example: Validate with logging (for server logs).
    ///
    /// - Parameters:
    ///   - sigStructure: CBOR-encoded Sig_structure bytes
    ///   - signatureDER: ASN.1 DER ECDSA signature bytes
    ///   - publicKey: Uncompressed P-256 public key
    /// - Returns: Tuple of result and logging info
    static func validateWithLogging(
        sigStructure: Data,
        signatureDER: Data,
        publicKey: Data
    ) -> (result: ServerAssertionValidationResult, logInfo: ServerValidationLogInfo) {
        guard let context = ServerAssertionValidationContext.create(
            sigStructure: sigStructure,
            signatureDER: signatureDER,
            publicKey: publicKey
        ) else {
            let dummyLogInfo = ServerValidationLogInfo(
                sigStructureHash: "",
                signatureLength: 0,
                publicKeyFingerprint: ""
            )
            return (.cannotValidate(reason: "Invalid input format"), dummyLogInfo)
        }
        
        return ServerAssertionValidator.validateWithLogging(context: context)
    }
    
    /// Example: Vapor route handler pattern.
    ///
    /// This shows how you might use the validator in a Vapor route:
    ///
    /// ```swift
    /// app.post("validate") { req -> Response in
    ///     let body = try req.content.decode(ValidationRequest.self)
    ///     
    ///     guard let sigStructure = Data(base64Encoded: body.sigStructureBase64),
    ///           let signatureDER = Data(base64Encoded: body.signatureDERBase64),
    ///           let publicKey = Data(base64Encoded: body.publicKeyBase64) else {
    ///         return Response(status: .badRequest, body: "Invalid base64 encoding")
    ///     }
    ///     
    ///     let result = ServerValidatorExample.validateAssertion(
    ///         sigStructure: sigStructure,
    ///         signatureDER: signatureDER,
    ///         publicKey: publicKey
    ///     )
    ///     
    ///     switch result {
    ///     case .verified:
    ///         return Response(status: .ok, body: "Verified")
    ///     case .failed(let reason):
    ///         return Response(status: .unauthorized, body: reason)
    ///     case .cannotValidate(let reason):
    ///         return Response(status: .badRequest, body: reason)
    ///     }
    /// }
    /// ```
    static func exampleVaporHandler(
        sigStructureBase64: String,
        signatureDERBase64: String,
        publicKeyBase64: String
    ) -> (statusCode: Int, message: String) {
        // Decode base64 inputs (this is the caller's responsibility)
        guard let sigStructure = Data(base64Encoded: sigStructureBase64),
              let signatureDER = Data(base64Encoded: signatureDERBase64),
              let publicKey = Data(base64Encoded: publicKeyBase64) else {
            return (400, "Invalid base64 encoding")
        }
        
        // Validate
        let result = validateAssertion(
            sigStructure: sigStructure,
            signatureDER: signatureDER,
            publicKey: publicKey
        )
        
        // Map to HTTP response
        switch result {
        case .verified:
            return (200, "Verified")
        case .failed(let reason):
            return (401, reason)
        case .cannotValidate(let reason):
            return (400, reason)
        }
    }
    
    /// Example: CLI usage pattern.
    ///
    /// This shows how you might use the validator from command line:
    ///
    /// ```bash
    /// ./validator \
    ///   --sig-structure "$(cat sig_structure.bin | base64)" \
    ///   --signature "$(cat signature.der | base64)" \
    ///   --public-key "$(cat public_key.bin | base64)"
    /// ```
    static func exampleCLIUsage(
        sigStructureBase64: String,
        signatureDERBase64: String,
        publicKeyBase64: String
    ) {
        guard let sigStructure = Data(base64Encoded: sigStructureBase64),
              let signatureDER = Data(base64Encoded: signatureDERBase64),
              let publicKey = Data(base64Encoded: publicKeyBase64) else {
            print("Error: Invalid base64 encoding")
            return
        }
        
        let (result, logInfo) = validateWithLogging(
            sigStructure: sigStructure,
            signatureDER: signatureDER,
            publicKey: publicKey
        )
        
        print("=== Validation Result ===")
        print("Result: \(result.description)")
        print()
        print("Logging Info:")
        print("  SHA256(sig_structure): \(logInfo.sigStructureHash)")
        print("  Signature length: \(logInfo.signatureLength) bytes")
        print("  Public key fingerprint: \(logInfo.publicKeyFingerprint)")
    }
}
