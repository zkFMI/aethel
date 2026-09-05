//! Explicit DeKYX provider boundary for Aethel.
//!
//! This crate intentionally does not depend on `aethel-core`. Its output is the
//! compatibility record Aethel stores next to a credit decision or guarantee.
//! That keeps Aethel's receivable state application-specific while DeKYX owns
//! issuer trust, key epochs, qualifications, revocation, and the ZK
//! presentation.

use dekyx_core::{
    AnonymousPresentation, DeKyxError, Digest32, EligibilityProvider, EligibilityRequirement,
    Identifier, IssuerDirectory, PresentationContext, Qualification, SubjectKind,
};
use serde::{Deserialize, Serialize};

/// What Aethel asks DeKYX to verify for one provider artifact on one anonymous
/// line. `request_id` is the line scope; `artifact_digest` and `challenge_nonce`
/// bind the presentation to exactly one credit decision or guarantee.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AethelEligibilityRequest {
    pub request_id: Identifier,
    pub issuer_provider_id: Identifier,
    pub issuer_key_epoch: u64,
    pub issuer_namespace_digest: Digest32,
    pub subject_kind: SubjectKind,
    pub policy_digest: Digest32,
    pub required_qualifications: Vec<Qualification>,
    pub audience_digest: Digest32,
    pub action_digest: Digest32,
    pub artifact_digest: Digest32,
    pub challenge_nonce: Identifier,
    pub valid_until: u64,
}

impl AethelEligibilityRequest {
    pub fn context(&self) -> PresentationContext {
        PresentationContext {
            scope_digest: self.request_id,
            audience_digest: self.audience_digest,
            action_digest: self.action_digest,
            request_digest: self.artifact_digest,
            challenge_nonce: self.challenge_nonce,
            valid_until: self.valid_until,
        }
    }

    pub fn requirement(&self) -> EligibilityRequirement {
        EligibilityRequirement {
            issuer_id: self.issuer_provider_id,
            issuer_key_epoch: self.issuer_key_epoch,
            issuer_namespace_digest: self.issuer_namespace_digest,
            subject_kind: self.subject_kind,
            scope_digest: self.request_id,
            policy_digest: self.policy_digest,
            required_qualifications: self.required_qualifications.clone(),
        }
    }
}

/// The record Aethel stores for an anonymous line: the meaning of the former
/// Aethel-owned confidential subject, now produced only by DeKYX verification.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AethelSubjectBinding {
    pub request_id: Identifier,
    pub issuer_provider_id: Identifier,
    pub issuer_key_epoch: u64,
    pub issuer_namespace_digest: Digest32,
    pub subject_kind: SubjectKind,
    pub subject_commitment: Digest32,
    pub scope_digest: Digest32,
    pub policy_digest: Digest32,
    pub subject_nullifier: Identifier,
    pub proof_digest: Digest32,
    pub subject_line_id: Digest32,
    pub valid_until: u64,
}

impl AethelSubjectBinding {
    /// Credit and guarantee may use fresh proof transcripts, and the issuer may
    /// have rotated its key or re-issued the credential in between, but they
    /// must bind to the same issuer, scope, policy, and scope nullifier.
    pub fn same_subject_line(&self, other: &Self) -> bool {
        self.request_id == other.request_id
            && self.issuer_provider_id == other.issuer_provider_id
            && self.issuer_namespace_digest == other.issuer_namespace_digest
            && self.subject_kind == other.subject_kind
            && self.scope_digest == other.scope_digest
            && self.policy_digest == other.policy_digest
            && self.subject_nullifier == other.subject_nullifier
            && self.subject_line_id == other.subject_line_id
    }
}

/// Verifies Aethel presentations against a DeKYX issuer directory. The
/// directory decides which issuer key epochs are live and which credentials
/// are revoked; the adapter only shapes the request and the stored record.
pub struct AethelDeKyxAdapter<'a> {
    pub directory: &'a IssuerDirectory,
}

impl AethelDeKyxAdapter<'_> {
    pub fn verify(
        &self,
        request: &AethelEligibilityRequest,
        presentation: &AnonymousPresentation,
        now: u64,
    ) -> Result<AethelSubjectBinding, DeKyxError> {
        if presentation.credential.issuer_id != request.issuer_provider_id
            || presentation.credential.issuer_key_epoch != request.issuer_key_epoch
        {
            return Err(DeKyxError::RequirementMismatch);
        }
        let verifier = self
            .directory
            .verifier(&request.issuer_provider_id, request.issuer_key_epoch)?;
        let context = request.context();
        let verified =
            verifier.verify_eligibility(&request.requirement(), &context, presentation, now)?;
        if verified.issuer_id != request.issuer_provider_id
            || verified.issuer_key_epoch != request.issuer_key_epoch
            || verified.issuer_namespace_digest != request.issuer_namespace_digest
            || verified.subject_kind != request.subject_kind
        {
            return Err(DeKyxError::RequirementMismatch);
        }
        Ok(AethelSubjectBinding {
            request_id: request.request_id,
            issuer_provider_id: verified.issuer_id,
            issuer_key_epoch: verified.issuer_key_epoch,
            issuer_namespace_digest: verified.issuer_namespace_digest,
            subject_kind: verified.subject_kind,
            subject_commitment: verified.subject_commitment,
            scope_digest: request.request_id,
            policy_digest: verified.policy_digest,
            subject_nullifier: verified.subject_nullifier,
            proof_digest: verified.proof_digest,
            subject_line_id: verified.subject_line_id,
            valid_until: verified.valid_until,
        })
    }
}
