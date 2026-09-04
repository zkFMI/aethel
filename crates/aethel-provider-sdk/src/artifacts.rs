//! Provider-signed artifacts: the outputs of credit assessors, guarantors,
//! liquidity providers, and servicers. Each carries a statement digest over
//! its unsigned form and the provider's Ed25519 signature over that digest.

use serde::{Deserialize, Serialize};

use aethel_types::{digest, Commitment, Identifier, MAX_UNIX_TIME, ZERO};

use crate::ProviderError;

const CREDIT_DECISION_DOMAIN: &[u8] = b"AETHEL:CREDIT-DECISION:v1";
const GUARANTEE_DOMAIN: &[u8] = b"AETHEL:GUARANTEE-COMMITMENT:v1";
const FUNDING_QUOTE_DOMAIN: &[u8] = b"AETHEL:FUNDING-QUOTE:v1";
const DEFAULT_DOMAIN: &[u8] = b"AETHEL:DEFAULT-ATTESTATION:v1";
const GUARANTEE_RELEASE_DOMAIN: &[u8] = b"AETHEL:GUARANTEE-RELEASE:v1";

/// A private-policy underwriting result.  It is information, not a promise to
/// absorb loss and not a promise to advance funds.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreditDecision {
    pub operation_id: Identifier,
    pub decision_id: Identifier,
    pub request_id: Identifier,
    pub provider_id: Identifier,
    pub series_id: Identifier,
    pub stream_state_version: u64,
    pub stream_state_root: Commitment,
    pub model_digest: Commitment,
    pub policy_digest: Commitment,
    pub decision_terms_commitment: Commitment,
    pub relation_proof_digest: Commitment,
    pub valid_until: u64,
    pub nonce: Identifier,
    pub signature: Vec<u8>,
}

impl CreditDecision {
    pub fn statement(&self) -> Result<Commitment, ProviderError> {
        if [
            self.operation_id,
            self.decision_id,
            self.request_id,
            self.provider_id,
            self.series_id,
            self.stream_state_root,
            self.model_digest,
            self.policy_digest,
            self.decision_terms_commitment,
            self.relation_proof_digest,
            self.nonce,
        ]
        .contains(&ZERO)
            || self.stream_state_version == 0
            || self.valid_until == 0
            || self.valid_until > MAX_UNIX_TIME
        {
            return Err(ProviderError::InvalidCreditDecision);
        }
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        Ok(digest(CREDIT_DECISION_DOMAIN, &unsigned)?)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LossLayer {
    FirstLoss,
    PariPassu,
    Excess,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuaranteeStatus {
    Available,
    Bound,
    Claimed,
    Released,
}

/// A binding risk-capital commitment backed by an authoritative DeFMI hold.
/// This is intentionally distinct from [`CreditDecision`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuaranteeCommitment {
    pub operation_id: Identifier,
    pub guarantee_id: Identifier,
    pub request_id: Identifier,
    pub provider_id: Identifier,
    pub series_id: Identifier,
    pub stream_state_version: u64,
    pub stream_state_root: Commitment,
    pub credit_decision_id: Option<Identifier>,
    pub defmi_facility_id: Identifier,
    pub defmi_hold_id: Identifier,
    pub coverage_commitment: Commitment,
    pub loss_layer: LossLayer,
    pub guarantee_terms_digest: Commitment,
    pub claim_policy_digest: Commitment,
    pub relation_proof_digest: Commitment,
    pub valid_until: u64,
    pub nonce: Identifier,
    pub signature: Vec<u8>,
    pub status: GuaranteeStatus,
    pub bound_issuance_id: Option<Identifier>,
}

impl GuaranteeCommitment {
    pub fn statement(&self) -> Result<Commitment, ProviderError> {
        if [
            self.operation_id,
            self.guarantee_id,
            self.request_id,
            self.provider_id,
            self.series_id,
            self.stream_state_root,
            self.defmi_facility_id,
            self.defmi_hold_id,
            self.coverage_commitment,
            self.guarantee_terms_digest,
            self.claim_policy_digest,
            self.relation_proof_digest,
            self.nonce,
        ]
        .contains(&ZERO)
            || self.credit_decision_id == Some(ZERO)
            || self.stream_state_version == 0
            || self.valid_until == 0
            || self.valid_until > MAX_UNIX_TIME
            || self.status != GuaranteeStatus::Available
            || self.bound_issuance_id.is_some()
        {
            return Err(ProviderError::InvalidGuarantee);
        }
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        Ok(digest(GUARANTEE_DOMAIN, &unsigned)?)
    }
}

/// The guarantor withdraws an unbound guarantee, or lets an expired one go.
/// The host verifies that `defmi_settlement_digest` is the DeFMI release of
/// the backing hold and that DeCCP returned the hidden capacity through a
/// verified transition before Aethel marks the guarantee released.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuaranteeRelease {
    pub operation_id: Identifier,
    pub guarantee_id: Identifier,
    pub provider_id: Identifier,
    pub defmi_settlement_digest: Commitment,
    pub relation_proof_digest: Commitment,
    pub released_at: u64,
    pub signature: Vec<u8>,
}

impl GuaranteeRelease {
    pub fn statement(&self) -> Result<Commitment, ProviderError> {
        if [
            self.operation_id,
            self.guarantee_id,
            self.provider_id,
            self.defmi_settlement_digest,
            self.relation_proof_digest,
        ]
        .contains(&ZERO)
            || self.released_at == 0
            || self.released_at > MAX_UNIX_TIME
        {
            return Err(ProviderError::InvalidGuaranteeRelease);
        }
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        Ok(digest(GUARANTEE_RELEASE_DOMAIN, &unsigned)?)
    }
}

/// An executable advance quote backed by a cash-note reservation in DeFMI.
/// An underwriter may also be the liquidity provider, but this interface never
/// assumes that the two legal obligations are the same.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FundingQuote {
    pub operation_id: Identifier,
    pub quote_id: Identifier,
    pub request_id: Identifier,
    pub provider_id: Identifier,
    pub series_id: Identifier,
    pub stream_state_version: u64,
    pub stream_state_root: Commitment,
    pub credit_decision_id: Option<Identifier>,
    pub guarantee_id: Option<Identifier>,
    pub cash_asset_id: Identifier,
    pub cash_reservation_id: Identifier,
    pub advance_commitment: Commitment,
    pub price_commitment: Commitment,
    pub quote_terms_digest: Commitment,
    pub policy_digest: Commitment,
    pub relation_proof_digest: Commitment,
    pub valid_until: u64,
    pub nonce: Identifier,
    pub signature: Vec<u8>,
    pub bound_issuance_id: Option<Identifier>,
}

impl FundingQuote {
    pub fn statement(&self) -> Result<Commitment, ProviderError> {
        if [
            self.operation_id,
            self.quote_id,
            self.request_id,
            self.provider_id,
            self.series_id,
            self.stream_state_root,
            self.cash_asset_id,
            self.cash_reservation_id,
            self.advance_commitment,
            self.price_commitment,
            self.quote_terms_digest,
            self.policy_digest,
            self.relation_proof_digest,
            self.nonce,
        ]
        .contains(&ZERO)
            || self.credit_decision_id == Some(ZERO)
            || self.guarantee_id == Some(ZERO)
            || self.stream_state_version == 0
            || self.valid_until == 0
            || self.valid_until > MAX_UNIX_TIME
            || self.bound_issuance_id.is_some()
        {
            return Err(ProviderError::InvalidFundingQuote);
        }
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        Ok(digest(FUNDING_QUOTE_DOMAIN, &unsigned)?)
    }
}

/// A servicer's signed observation that the contractually defined default
/// condition occurred.  It is evidence for a claim, not the payout itself.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DefaultAttestation {
    pub operation_id: Identifier,
    pub attestation_id: Identifier,
    pub provider_id: Identifier,
    pub stream_id: Identifier,
    pub stream_state_version: u64,
    pub stream_state_root: Commitment,
    pub event_digest: Commitment,
    pub reason_digest: Commitment,
    pub observed_at: u64,
    pub signature: Vec<u8>,
}

impl DefaultAttestation {
    pub fn statement(&self) -> Result<Commitment, ProviderError> {
        if [
            self.operation_id,
            self.attestation_id,
            self.provider_id,
            self.stream_id,
            self.stream_state_root,
            self.event_digest,
            self.reason_digest,
        ]
        .contains(&ZERO)
            || self.stream_state_version == 0
            || self.observed_at == 0
            || self.observed_at > MAX_UNIX_TIME
        {
            return Err(ProviderError::InvalidDefaultAttestation);
        }
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        Ok(digest(DEFAULT_DOMAIN, &unsigned)?)
    }
}
