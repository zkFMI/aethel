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
//!
//! The provider contract (capabilities, artifact keys, and every
//! provider-signed artifact type) lives in `aethel-provider-sdk` so a provider
//! can integrate without this state machine; the shared identifier and digest
//! primitives live in `aethel-types`. Both are re-exported here under their
//! original names, so callers written against earlier versions of this crate
//! compile unchanged.

#![forbid(unsafe_code)]

mod book;
mod receivable;
mod subject;

pub use book::{AethelBook, AethelError, RegisteredStream};
pub use subject::{ConfidentialArtifact, ConfidentialSubjectBinding};

/// DeKYX is the identity layer this crate adapts to. It is re-exported so an
/// application adapter and its tests build credentials and presentations with
/// exactly the version Aethel verifies against.
pub use dekyx_aethel;
pub use dekyx_core;

/// The provider contract and the shared primitives, re-exported whole for
/// callers that want to name the crate boundary explicitly.
pub use aethel_provider_sdk;
pub use aethel_types;

pub use aethel_provider_sdk::{
    sign_artifact, CreditDecision, DefaultAttestation, FundingQuote, GuaranteeCommitment,
    GuaranteeRelease, GuaranteeStatus, LossLayer, ProviderCapability, ProviderDefinition,
    ProviderError, ProviderRegistry, ProviderStatus, PublishCredentialStatus,
    RegisterCredentialIssuer, RegisterProvider, RegisterStream, RetiredProviderKey,
    RotateProviderKey, SetProviderStatus, SignedArtifact, StreamState, StreamStatus,
    StreamTransition,
};
pub use aethel_types::{Commitment, Identifier, MAX_UNIX_TIME, ZERO};
pub use receivable::{
    GuaranteeClaim, ReceivableIssuance, ReceivableSeries, ReceivableStatus, RegisterSeries,
    SeriesPolicy,
};

pub(crate) use aethel_types::{id_key, valid_window};

use serde::Serialize;

pub(crate) fn digest<T: Serialize>(domain: &[u8], value: &T) -> Result<Commitment, AethelError> {
    aethel_types::digest(domain, value).map_err(|_| AethelError::Encoding)
}
