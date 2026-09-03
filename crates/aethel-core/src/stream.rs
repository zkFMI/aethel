use serde::{Deserialize, Serialize};

use crate::{digest, AethelError, Commitment, Identifier, MAX_UNIX_TIME, ZERO};

const STREAM_STATE_DOMAIN: &[u8] = b"AETHEL:STREAM-STATE:v1";
const STREAM_REGISTRATION_DOMAIN: &[u8] = b"AETHEL:STREAM-REGISTRATION:v1";
const STREAM_TRANSITION_DOMAIN: &[u8] = b"AETHEL:STREAM-TRANSITION:v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamStatus {
    Active,
    Paused,
    Cancelled,
    Defaulted,
    Closed,
}

/// Canonical, lazy-accrual state of a payment stream.
///
/// Amounts are commitments. The attestor signature authenticates their data
/// source and the named relation-proof digest binds optional source-specific
/// arithmetic or covenant evidence. This generic state machine does not infer
/// that evidence from the digest; an adapter must invoke its registered
/// verifier when a deployment requires it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamState {
    pub stream_id: Identifier,
    pub payer_commitment: Commitment,
    pub payee_commitment: Commitment,
    pub settlement_asset_id: Identifier,
    pub source_domain_digest: Commitment,
    pub terms_digest: Commitment,
    pub event_root: Commitment,
    pub accrued_commitment: Commitment,
    pub paid_commitment: Commitment,
    pub eligible_commitment: Commitment,
    pub pledged_commitment: Commitment,
    pub as_of: u64,
    pub version: u64,
    pub status: StreamStatus,
}

impl StreamState {
    pub fn validate(&self) -> Result<(), AethelError> {
        if [
            self.stream_id,
            self.payer_commitment,
            self.payee_commitment,
            self.settlement_asset_id,
            self.source_domain_digest,
            self.terms_digest,
            self.event_root,
        ]
        .contains(&ZERO)
            || self.payer_commitment == self.payee_commitment
            || self.as_of == 0
            || self.as_of > MAX_UNIX_TIME
            || self.version == 0
        {
            return Err(AethelError::InvalidStream);
        }
        Ok(())
    }

    pub fn root(&self) -> Result<Commitment, AethelError> {
        self.validate()?;
        digest(STREAM_STATE_DOMAIN, self)
    }

    pub(crate) fn valid_source_successor(&self, next: &Self) -> bool {
        next.stream_id == self.stream_id
            && next.payer_commitment == self.payer_commitment
            && next.payee_commitment == self.payee_commitment
            && next.settlement_asset_id == self.settlement_asset_id
            && next.source_domain_digest == self.source_domain_digest
            && next.terms_digest == self.terms_digest
            && next.pledged_commitment == self.pledged_commitment
            && next.version == self.version + 1
            && next.as_of > self.as_of
            && valid_status_transition(self.status, next.status)
    }

    pub fn valid_issuance_successor(
        &self,
        after_pledged_commitment: Commitment,
    ) -> Result<Self, AethelError> {
        if matches!(
            self.status,
            StreamStatus::Cancelled | StreamStatus::Defaulted | StreamStatus::Closed
        ) {
            return Err(AethelError::StreamUnavailable);
        }
        let mut next = self.clone();
        next.version = next
            .version
            .checked_add(1)
            .ok_or(AethelError::ArithmeticOverflow)?;
        next.pledged_commitment = after_pledged_commitment;
        Ok(next)
    }
}

fn valid_status_transition(before: StreamStatus, after: StreamStatus) -> bool {
    use StreamStatus::*;
    matches!(
        (before, after),
        (Active, Active | Paused | Cancelled | Defaulted | Closed)
            | (Paused, Active | Paused | Cancelled | Defaulted | Closed)
            | (Cancelled, Cancelled | Closed)
            | (Defaulted, Defaulted | Closed)
            | (Closed, Closed)
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterStream {
    pub operation_id: Identifier,
    pub attestor_provider_id: Identifier,
    pub state: StreamState,
    pub source_evidence_digest: Commitment,
    pub relation_proof_digest: Commitment,
    pub signature: Vec<u8>,
}

impl RegisterStream {
    pub fn statement(&self) -> Result<Commitment, AethelError> {
        if [
            self.operation_id,
            self.attestor_provider_id,
            self.source_evidence_digest,
            self.relation_proof_digest,
        ]
        .contains(&ZERO)
            || self.state.version != 1
            || self.state.status != StreamStatus::Active
        {
            return Err(AethelError::InvalidStream);
        }
        self.state.validate()?;
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        digest(STREAM_REGISTRATION_DOMAIN, &unsigned)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamTransition {
    pub operation_id: Identifier,
    pub attestor_provider_id: Identifier,
    pub before_state_root: Commitment,
    pub after_state: StreamState,
    pub source_evidence_digest: Commitment,
    pub relation_proof_digest: Commitment,
    pub signature: Vec<u8>,
}

impl StreamTransition {
    pub fn statement(&self) -> Result<Commitment, AethelError> {
        if [
            self.operation_id,
            self.attestor_provider_id,
            self.before_state_root,
            self.source_evidence_digest,
            self.relation_proof_digest,
        ]
        .contains(&ZERO)
        {
            return Err(AethelError::InvalidStreamTransition);
        }
        self.after_state.validate()?;
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        digest(STREAM_TRANSITION_DOMAIN, &unsigned)
    }
}
