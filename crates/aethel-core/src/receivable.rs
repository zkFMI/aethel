use dekyx_core::{Qualification, SubjectKind};
use serde::{Deserialize, Serialize};

use crate::{digest, valid_window, AethelError, Commitment, Identifier, MAX_UNIX_TIME, ZERO};

const SERIES_DOMAIN: &[u8] = b"AETHEL:RECEIVABLE-SERIES:v1";
const ISSUANCE_DOMAIN: &[u8] = b"AETHEL:RECEIVABLE-ISSUANCE:v1";
const GUARANTEE_CLAIM_DOMAIN: &[u8] = b"AETHEL:GUARANTEE-CLAIM:v1";

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
