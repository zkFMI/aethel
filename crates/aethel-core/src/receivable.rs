use dekyx_core::{Qualification, SubjectKind};
use serde::{Deserialize, Serialize};

use crate::{digest, valid_window, AethelError, Commitment, Identifier, MAX_UNIX_TIME, ZERO};

const SERIES_DOMAIN: &[u8] = b"AETHEL:RECEIVABLE-SERIES:v1";
const CREDIT_DECISION_DOMAIN: &[u8] = b"AETHEL:CREDIT-DECISION:v1";
const GUARANTEE_DOMAIN: &[u8] = b"AETHEL:GUARANTEE-COMMITMENT:v1";
const FUNDING_QUOTE_DOMAIN: &[u8] = b"AETHEL:FUNDING-QUOTE:v1";
const ISSUANCE_DOMAIN: &[u8] = b"AETHEL:RECEIVABLE-ISSUANCE:v1";
const DEFAULT_DOMAIN: &[u8] = b"AETHEL:DEFAULT-ATTESTATION:v1";
const GUARANTEE_CLAIM_DOMAIN: &[u8] = b"AETHEL:GUARANTEE-CLAIM:v1";
const GUARANTEE_RELEASE_DOMAIN: &[u8] = b"AETHEL:GUARANTEE-RELEASE:v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceivableStatus {
    Active,
    Suspended,
    Closed,
}

/// Deterministic admission rules for one receivable series.
///
/// The rules say which artifacts are mandatory. Private thresholds such as
/// minimum coverage, concentration, and advance-rate limits stay in
/// `eligibility_policy_digest`. The generic issuance zkPI binds that policy and
/// proves stream capacity; policy-specific predicates need their registered
/// verifier rather than being inferred from the digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SeriesPolicy {
    pub requires_credit_decision: bool,
    pub requires_guarantee: bool,
    pub requires_funding_reservation: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub requires_confidential_subject: bool,
    /// DeKYX subject kind an anonymous line must be credentialed as. A
    /// receivable line is a legal entity (KYB) unless the series says otherwise.
    #[serde(default = "legal_entity", skip_serializing_if = "is_legal_entity")]
    pub subject_kind: SubjectKind,
    /// DeKYX qualifications the holder must disclose and prove for every
    /// credit decision and guarantee on the line. Empty means credential
    /// possession alone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_qualifications: Vec<Qualification>,
    /// When set, only DeKYX issuers registered under this namespace digest
    /// may credential the line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_issuer_namespace_digest: Option<Commitment>,
    pub allow_secondary_transfer: bool,
    pub eligibility_policy_digest: Commitment,
    pub claim_policy_digest: Commitment,
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn legal_entity() -> SubjectKind {
    SubjectKind::LegalEntity
}

fn is_legal_entity(kind: &SubjectKind) -> bool {
    *kind == SubjectKind::LegalEntity
}

impl SeriesPolicy {
    fn validate(&self) -> Result<(), AethelError> {
        if self.eligibility_policy_digest == ZERO
            || self.claim_policy_digest == ZERO
            || self.accepted_issuer_namespace_digest == Some(ZERO)
            || self.required_qualifications.len() > 256
            || (self.requires_confidential_subject
                && !self.requires_credit_decision
                && !self.requires_guarantee)
        {
            return Err(AethelError::InvalidSeries);
        }
        let mut seen = std::collections::BTreeSet::new();
        for qualification in &self.required_qualifications {
            qualification
                .validate()
                .map_err(|_| AethelError::InvalidSeries)?;
            if !seen.insert(qualification) {
                return Err(AethelError::InvalidSeries);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceivableSeries {
    pub series_id: Identifier,
    pub aethel_domain_id: Identifier,
    pub stream_id: Identifier,
    pub receivable_asset_id: Identifier,
    pub issuer_participant_id: Identifier,
    pub policy: SeriesPolicy,
    pub valid_from: u64,
    pub maturity: u64,
    pub sequence: u64,
    pub status: ReceivableStatus,
}

impl ReceivableSeries {
    pub fn validate_initial(&self) -> Result<(), AethelError> {
        if [
            self.series_id,
            self.aethel_domain_id,
            self.stream_id,
            self.receivable_asset_id,
            self.issuer_participant_id,
        ]
        .contains(&ZERO)
            || !valid_window(self.valid_from, self.maturity)
            || self.sequence != 0
            || self.status != ReceivableStatus::Active
        {
            return Err(AethelError::InvalidSeries);
        }
        self.policy.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterSeries {
    pub operation_id: Identifier,
    pub series: ReceivableSeries,
}

impl RegisterSeries {
    pub fn statement(&self) -> Result<Commitment, AethelError> {
        if self.operation_id == ZERO {
            return Err(AethelError::InvalidSeries);
        }
        self.series.validate_initial()?;
        digest(SERIES_DOMAIN, self)
    }
}

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
    pub fn statement(&self) -> Result<Commitment, AethelError> {
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
            return Err(AethelError::InvalidCreditDecision);
        }
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        digest(CREDIT_DECISION_DOMAIN, &unsigned)
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
    pub fn statement(&self) -> Result<Commitment, AethelError> {
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
            return Err(AethelError::InvalidGuarantee);
        }
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        digest(GUARANTEE_DOMAIN, &unsigned)
    }
}

/// The guarantor withdraws an unbound guarantee, or lets an expired one go.
/// The Avalanche VM verifies that `defmi_settlement_digest` is the DeFMI
/// release of the backing hold and that DeCCP returned the hidden capacity
/// through a verified transition before Aethel marks the guarantee released.
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
    pub fn statement(&self) -> Result<Commitment, AethelError> {
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
            return Err(AethelError::InvalidGuaranteeRelease);
        }
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        digest(GUARANTEE_RELEASE_DOMAIN, &unsigned)
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
    pub fn statement(&self) -> Result<Commitment, AethelError> {
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
            return Err(AethelError::InvalidFundingQuote);
        }
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        digest(FUNDING_QUOTE_DOMAIN, &unsigned)
    }
}

/// The Aethel-to-DeFMI binding for one issued receivable note.
///
/// The typed zkPI proves that the committed face value, post-issuance pledged
/// amount, selected decision/guarantee/funding artifacts, and the DeFMI note
/// refer to the same request and current stream state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceivableIssuance {
    pub operation_id: Identifier,
    pub issuance_id: Identifier,
    pub request_id: Identifier,
    pub series_id: Identifier,
    pub note_id: Identifier,
    pub owner_commitment: Commitment,
    pub face_value_commitment: Commitment,
    pub before_stream_state_version: u64,
    pub before_stream_state_root: Commitment,
    pub after_pledged_commitment: Commitment,
    pub allocation_nullifier: Identifier,
    pub credit_decision_id: Option<Identifier>,
    pub guarantee_id: Option<Identifier>,
    pub funding_quote_id: Option<Identifier>,
    pub relation_proof_digest: Commitment,
    pub zkpi_digest: Commitment,
    pub issued_at: u64,
}

impl ReceivableIssuance {
    pub fn statement(&self) -> Result<Commitment, AethelError> {
        if [
            self.operation_id,
            self.issuance_id,
            self.request_id,
            self.series_id,
            self.note_id,
            self.owner_commitment,
            self.face_value_commitment,
            self.before_stream_state_root,
            self.after_pledged_commitment,
            self.allocation_nullifier,
            self.relation_proof_digest,
            self.zkpi_digest,
        ]
        .contains(&ZERO)
            || self.credit_decision_id == Some(ZERO)
            || self.guarantee_id == Some(ZERO)
            || self.funding_quote_id == Some(ZERO)
            || self.before_stream_state_version == 0
            || self.issued_at == 0
            || self.issued_at > MAX_UNIX_TIME
        {
            return Err(AethelError::InvalidIssuance);
        }
        digest(ISSUANCE_DOMAIN, self)
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
    pub fn statement(&self) -> Result<Commitment, AethelError> {
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
            return Err(AethelError::InvalidDefaultAttestation);
        }
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        digest(DEFAULT_DOMAIN, &unsigned)
    }
}

/// Records completion of the DeFMI-backed guarantee claim.  The Avalanche VM
/// verifies that `defmi_settlement_digest` is the settlement which consumed
/// the guarantee hold for exactly this committed amount.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuaranteeClaim {
    pub operation_id: Identifier,
    pub claim_id: Identifier,
    pub guarantee_id: Identifier,
    pub issuance_id: Identifier,
    pub default_attestation_id: Identifier,
    pub claim_amount_commitment: Commitment,
    pub recovery_recipient_commitment: Commitment,
    pub defmi_settlement_digest: Commitment,
    pub relation_proof_digest: Commitment,
    pub zkpi_digest: Commitment,
    pub claimed_at: u64,
}

impl GuaranteeClaim {
    pub fn statement(&self) -> Result<Commitment, AethelError> {
        if [
            self.operation_id,
            self.claim_id,
            self.guarantee_id,
            self.issuance_id,
            self.default_attestation_id,
            self.claim_amount_commitment,
            self.recovery_recipient_commitment,
            self.defmi_settlement_digest,
            self.relation_proof_digest,
            self.zkpi_digest,
        ]
        .contains(&ZERO)
            || self.claimed_at == 0
            || self.claimed_at > MAX_UNIX_TIME
        {
            return Err(AethelError::InvalidGuaranteeClaim);
        }
        digest(GUARANTEE_CLAIM_DOMAIN, self)
    }
}
