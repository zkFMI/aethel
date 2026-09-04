//! Data-only primitives shared by every Aethel crate.
//!
//! This crate holds no state and no policy. It defines the identifier and
//! commitment widths every Aethel record uses, the canonical domain-separated
//! digest over a serialized record, and the two checks every crate applies to
//! untrusted wire values before it changes state: a validity window and an
//! Ed25519 signature over a statement digest.
//!
//! Everything here is pure. A value that passes these checks is well formed,
//! not yet authorized; authorization is the calling crate's decision.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// A 32-byte protocol identifier (operation, provider, stream, series, ...).
pub type Identifier = [u8; 32];
/// A 32-byte commitment or digest whose opening the record does not carry.
pub type Commitment = [u8; 32];

/// The all-zero value, which no valid identifier or commitment may take.
pub const ZERO: [u8; 32] = [0; 32];
/// Upper bound for every Unix timestamp on the wire.
pub const MAX_UNIX_TIME: u64 = i64::MAX as u64;

/// Canonical map key for an identifier: lower-case hex.
pub fn id_key(id: &Identifier) -> String {
    hex::encode(id)
}

/// `true` when `value` is the lower-case hex form [`id_key`] produces.
pub fn is_hex_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// A Unix time that is set and representable.
pub fn valid_time(at: u64) -> bool {
    at > 0 && at <= MAX_UNIX_TIME
}

/// A validity window with a set start no later than its end.
pub fn valid_window(valid_from: u64, valid_until: u64) -> bool {
    valid_from > 0 && valid_from <= valid_until && valid_until <= MAX_UNIX_TIME
}

/// `true` when any of `ids` is [`ZERO`].
pub fn any_zero(ids: &[[u8; 32]]) -> bool {
    ids.contains(&ZERO)
}

/// The record could not be serialized canonically.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("Aethel record encoding failed")]
pub struct EncodingError;

/// Domain-separated SHA-256 over the canonical JSON encoding of `value`:
/// `H(domain || len(encoding) || encoding)`. Every Aethel statement digest is
/// computed this way so a digest from one record type never collides with a
/// digest from another.
pub fn digest<T: Serialize>(domain: &[u8], value: &T) -> Result<Commitment, EncodingError> {
    let encoded = serde_json::to_vec(value).map_err(|_| EncodingError)?;
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update((encoded.len() as u64).to_be_bytes());
    hash.update(encoded);
    Ok(hash.finalize().into())
}

/// Why an Ed25519 signature over a statement was not accepted.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SignatureError {
    #[error("public key is not a valid Ed25519 key")]
    InvalidKey,
    #[error("signature does not verify against the statement")]
    InvalidSignature,
}

/// Verifies an Ed25519 signature over a statement digest.
pub fn verify_key_signature(
    public_key: &[u8; 32],
    statement: &Commitment,
    signature: &[u8],
) -> Result<(), SignatureError> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| SignatureError::InvalidKey)?;
    let signature =
        Signature::from_slice(signature).map_err(|_| SignatureError::InvalidSignature)?;
    key.verify(statement, &signature)
        .map_err(|_| SignatureError::InvalidSignature)
}

/// `true` when `public_key` decodes as an Ed25519 verifying key.
pub fn is_verifying_key(public_key: &[u8; 32]) -> bool {
    VerifyingKey::from_bytes(public_key).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn digest_is_domain_separated_and_length_prefixed() {
        let a = digest(b"A", &[1u8, 2, 3]).unwrap();
        let b = digest(b"B", &[1u8, 2, 3]).unwrap();
        let c = digest(b"A", &[1u8, 2]).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_eq!(a, digest(b"A", &[1u8, 2, 3]).unwrap());
    }

    #[test]
    fn hex_ids_round_trip_and_reject_upper_case() {
        let key = id_key(&[0xab; 32]);
        assert!(is_hex_id(&key));
        assert!(!is_hex_id(&key.to_ascii_uppercase()));
        assert!(!is_hex_id(&key[..63]));
    }

    #[test]
    fn windows_and_times_are_bounded() {
        assert!(valid_window(1, 1));
        assert!(!valid_window(0, 1));
        assert!(!valid_window(2, 1));
        assert!(!valid_window(1, MAX_UNIX_TIME + 1));
        assert!(valid_time(MAX_UNIX_TIME));
        assert!(!valid_time(0));
    }

    #[test]
    fn signatures_verify_only_against_their_statement() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let statement = digest(b"T", &"statement").unwrap();
        let signature = key.sign(&statement).to_bytes();
        let public = key.verifying_key().to_bytes();
        assert_eq!(
            verify_key_signature(&public, &statement, &signature),
            Ok(())
        );
        assert_eq!(
            verify_key_signature(&public, &ZERO, &signature),
            Err(SignatureError::InvalidSignature)
        );
        assert_eq!(
            verify_key_signature(&public, &statement, &signature[..63]),
            Err(SignatureError::InvalidSignature)
        );
        assert!(is_verifying_key(&public));
    }
}
