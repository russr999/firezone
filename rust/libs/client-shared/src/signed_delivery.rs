//! Verification of signed policy/resource delivery (Phase 4).
//!
//! The portal signs the JSON encoding of the `resources` list with the
//! account's Ed25519 private key and delivers the account public key + the
//! signature in the `init` payload. The client verifies the signature before
//! trusting resources, detecting tampering or substitution of the unsigned
//! channel push.
//!
//! ## Status: warn-only
//!
//! Enforcement (rejecting resources on a bad/absent signature) is intentionally
//! NOT enabled yet. The signature is computed server-side over `Jason.encode!`
//! output; the client must reconstruct byte-identical input to verify. Until
//! that canonical-encoding parity is validated end-to-end against a running
//! portal, [`verify_resources`] is advisory: callers log a warning on failure
//! but still apply resources, preserving the prior behaviour for accounts
//! with or without a signing key. Flipping to enforcement is a one-line change
//! once parity is confirmed (see SELF_HOSTED_UNLOCK_PLAN.md Phase 4).

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};

/// Result of verifying a signed resources payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    /// The account provided no signing key / signature — unsigned delivery.
    /// Treated as valid for backwards compatibility.
    Unsigned,
    /// Signature present and valid.
    Valid,
    /// Signature present but did not verify against the message + public key.
    Invalid,
}

/// Verifies a Base64 Ed25519 `signature` over `message` against the Base64
/// `public_key`. `signature` / `public_key` are the `init` payload's
/// `resources_signature` / `signing_public_key`; `message` is the canonical
/// JSON encoding of the resources the signature covers.
pub fn verify_resources(
    message: &[u8],
    signature: Option<&str>,
    public_key: Option<&str>,
) -> Verification {
    let (Some(signature), Some(public_key)) = (signature, public_key) else {
        return Verification::Unsigned;
    };

    match verify(message, signature, public_key) {
        Ok(true) => Verification::Valid,
        _ => Verification::Invalid,
    }
}

fn verify(message: &[u8], signature_b64: &str, public_key_b64: &str) -> anyhow::Result<bool> {
    let sig_bytes = STANDARD.decode(signature_b64)?;
    let key_bytes = STANDARD.decode(public_key_b64)?;

    let key_array: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&key_array)?;

    let signature = Signature::from_slice(&sig_bytes)?;

    Ok(verifying_key.verify_strict(message, &signature).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    fn keypair() -> SigningKey {
        // Deterministic test key (not secret).
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn unsigned_when_no_signature_or_key() {
        assert_eq!(
            verify_resources(b"anything", None, None),
            Verification::Unsigned
        );
        assert_eq!(
            verify_resources(b"anything", Some("sig"), None),
            Verification::Unsigned
        );
    }

    #[test]
    fn valid_signature_verifies() {
        let key = keypair();
        let msg = b"[{\"id\":\"abc\"}]";
        let sig = STANDARD.encode(key.sign(msg).to_bytes());
        let pubkey = STANDARD.encode(key.verifying_key().to_bytes());

        assert_eq!(
            verify_resources(msg, Some(&sig), Some(&pubkey)),
            Verification::Valid
        );
    }

    #[test]
    fn tampered_message_is_invalid() {
        let key = keypair();
        let sig = STANDARD.encode(key.sign(b"original").to_bytes());
        let pubkey = STANDARD.encode(key.verifying_key().to_bytes());

        assert_eq!(
            verify_resources(b"tampered", Some(&sig), Some(&pubkey)),
            Verification::Invalid
        );
    }

    #[test]
    fn garbage_signature_is_invalid_not_panic() {
        let key = keypair();
        let pubkey = STANDARD.encode(key.verifying_key().to_bytes());
        assert_eq!(
            verify_resources(b"msg", Some("not-base64!!"), Some(&pubkey)),
            Verification::Invalid
        );
    }
}
