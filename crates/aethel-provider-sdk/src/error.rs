use dekyx_core::DeKyxError;
use thiserror::Error;

use aethel_types::{EncodingError, SignatureError};

/// Why a provider definition, control operation, or signed artifact was not
/// accepted. The messages are the ones Aethel's protocol crate reports for the
/// same conditions; it converts these one to one.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderError {
    #[error("Aethel state encoding failed")]
    Encoding,
    #[error("provider definition is invalid")]
    InvalidProvider,
    #[error("provider key is invalid")]
    InvalidProviderKey,
    #[error("provider signature is invalid")]
    InvalidSignature,
    #[error("guarantee-capable provider has no DeFMI guarantee authority")]
    MissingGuaranteeAuthority,
    #[error("provider is unknown")]
    UnknownProvider,
    #[error("provider lacks the required active capability")]
    MissingProviderCapability,
    #[error("stream state is invalid")]
    InvalidStream,
    #[error("stream transition is invalid")]
    InvalidStreamTransition,
    #[error("stream is not eligible for a new receivable")]
    StreamUnavailable,
    #[error("credit decision is invalid")]
    InvalidCreditDecision,
    #[error("guarantee commitment is invalid")]
    InvalidGuarantee,
    #[error("guarantee release is invalid")]
    InvalidGuaranteeRelease,
    #[error("funding quote is invalid")]
    InvalidFundingQuote,
    #[error("default attestation is invalid")]
    InvalidDefaultAttestation,
    #[error("credential issuer registration is invalid")]
    InvalidCredentialIssuer,
    #[error("credential status publication is invalid")]
    InvalidCredentialStatus,
    #[error("DeKYX rejected the subject evidence: {0}")]
    Credential(DeKyxError),
    #[error("arithmetic overflow")]
    ArithmeticOverflow,
}

impl From<EncodingError> for ProviderError {
    fn from(_: EncodingError) -> Self {
        Self::Encoding
    }
}

impl From<SignatureError> for ProviderError {
    fn from(error: SignatureError) -> Self {
        match error {
            SignatureError::InvalidKey => Self::InvalidProviderKey,
            SignatureError::InvalidSignature => Self::InvalidSignature,
        }
    }
}
