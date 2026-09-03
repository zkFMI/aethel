//! Aethel's protocol state above DeFMI and zkPI.
//!
//! Aethel does not copy DeFMI's asset, note, DvP, reservation, or guarantee
//! facility books.  This crate records what those primitives *mean* for a
//! streaming receivable: which signed stream state is current, which providers
//! are allowed to attest, underwrite, guarantee, fund, or service it, and which
//! exact combination was bound into a one-use receivable issuance.
//!
//! The Avalanche VM is the adapter between this state machine and DeFMI.  It
//! must verify referenced note/facility/reservation state and the typed zkPI
//! before calling the mutation methods exposed by [`AethelBook`].
//!
//! Identity is not Aethel's either. Which legal entity stands behind an
//! anonymous credit line is a DeKYX question: Aethel records which provider
//! vouches for a DeKYX issuer key and stores the binding DeKYX returns for one
//! exact provider artifact, and nothing else about the subject.

mod book;
mod provider;
mod receivable;
mod stream;
mod subject;

pub use book::{AethelBook, AethelError, RegisteredStream};
pub use subject::{
    ConfidentialArtifact, ConfidentialSubjectBinding, PublishCredentialStatus,
    RegisterCredentialIssuer,
};

/// DeKYX is the identity layer this crate adapts to. It is re-exported so an
/// application adapter and its tests build credentials and presentations with
/// exactly the version Aethel verifies against.
pub use dekyx_aethel;
pub use dekyx_core;
pub use provider::{
    ProviderCapability, ProviderDefinition, ProviderStatus, RegisterProvider, RetiredProviderKey,
    RotateProviderKey, SetProviderStatus,
};
pub use receivable::{
    CreditDecision, DefaultAttestation, FundingQuote, GuaranteeClaim, GuaranteeCommitment,
    GuaranteeRelease, GuaranteeStatus, LossLayer, ReceivableIssuance, ReceivableSeries,
    ReceivableStatus, RegisterSeries, SeriesPolicy,
};
pub use stream::{RegisterStream, StreamState, StreamStatus, StreamTransition};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub type Identifier = [u8; 32];
pub type Commitment = [u8; 32];

pub const ZERO: [u8; 32] = [0; 32];
pub const MAX_UNIX_TIME: u64 = i64::MAX as u64;

pub(crate) fn id_key(id: &Identifier) -> String {
    hex::encode(id)
}

pub(crate) fn valid_window(valid_from: u64, valid_until: u64) -> bool {
    valid_from > 0 && valid_from <= valid_until && valid_until <= MAX_UNIX_TIME
}

pub(crate) fn digest<T: Serialize>(domain: &[u8], value: &T) -> Result<Commitment, AethelError> {
    let encoded = serde_json::to_vec(value).map_err(|_| AethelError::Encoding)?;
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update((encoded.len() as u64).to_be_bytes());
    hash.update(encoded);
    Ok(hash.finalize().into())
}

/// A new artifact must be signed by the provider's current key.
pub(crate) fn verify_provider_signature(
    provider: &ProviderDefinition,
    statement: &Commitment,
    signature: &[u8],
) -> Result<(), AethelError> {
    verify_key_signature(&provider.public_key, statement, signature)
}

/// An artifact already in the book was verified against the key that was
/// current when it was recorded; after a rotation that key is retired, so
/// state validation accepts the current key or any retired one.
pub(crate) fn verify_recorded_provider_signature(
    provider: &ProviderDefinition,
    statement: &Commitment,
    signature: &[u8],
) -> Result<(), AethelError> {
    let signature = Signature::from_slice(signature).map_err(|_| AethelError::InvalidSignature)?;
    for public_key in provider.signing_keys() {
        let key =
            VerifyingKey::from_bytes(&public_key).map_err(|_| AethelError::InvalidProviderKey)?;
        if key.verify(statement, &signature).is_ok() {
            return Ok(());
        }
    }
    Err(AethelError::InvalidSignature)
}

pub(crate) fn verify_key_signature(
    public_key: &[u8; 32],
    statement: &Commitment,
    signature: &[u8],
) -> Result<(), AethelError> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| AethelError::InvalidProviderKey)?;
    let signature = Signature::from_slice(signature).map_err(|_| AethelError::InvalidSignature)?;
    key.verify(statement, &signature)
        .map_err(|_| AethelError::InvalidSignature)
}
