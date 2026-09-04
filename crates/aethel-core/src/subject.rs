//! Aethel's thin adapter onto DeKYX.
//!
//! Aethel keeps only what a receivable line needs: which provider vouches for
//! a DeKYX issuer key, which provider artifact a presentation is bound to, and
//! the DeKYX-produced binding stored beside that artifact. Issuer trust, key
//! epochs, credential signatures, qualifications, revocation, and the
//! zero-knowledge presentation belong to DeKYX and are not re-implemented here.
//! The requests a credential-issuer provider submits (`RegisterCredentialIssuer`,
//! `PublishCredentialStatus`) are part of the provider contract in
//! `aethel-provider-sdk`.

use dekyx_aethel::{AethelEligibilityRequest, AethelSubjectBinding};
use dekyx_core::{IssuerDefinition, PresentationContext};
use sha2::{Digest, Sha256};

use crate::{
    AethelError, Commitment, CreditDecision, GuaranteeCommitment, Identifier, ReceivableSeries,
    ZERO,
};

const CREDIT_DECISION_ACTION_DOMAIN: &[u8] = b"AETHEL:SUBJECT-ACTION:CREDIT-DECISION:v1";
const GUARANTEE_ACTION_DOMAIN: &[u8] = b"AETHEL:SUBJECT-ACTION:GUARANTEE:v1";

/// The record Aethel stores for an anonymous line. It is produced only by
/// DeKYX verification; Aethel never constructs one from unverified input.
pub type ConfidentialSubjectBinding = AethelSubjectBinding;

/// The provider artifact a subject presentation is bound to. The holder
/// proves against the exact unsigned artifact, so a transcript cannot be moved
/// to another decision, another guarantee, or another line.
#[derive(Clone, Copy, Debug)]
pub enum ConfidentialArtifact<'a> {
    CreditDecision(&'a CreditDecision),
    Guarantee(&'a GuaranteeCommitment),
}

impl ConfidentialArtifact<'_> {
    pub fn request_id(&self) -> Identifier {
        match self {
            Self::CreditDecision(decision) => decision.request_id,
            Self::Guarantee(guarantee) => guarantee.request_id,
        }
    }

    pub fn series_id(&self) -> Identifier {
        match self {
            Self::CreditDecision(decision) => decision.series_id,
            Self::Guarantee(guarantee) => guarantee.series_id,
        }
    }

    pub fn nonce(&self) -> Identifier {
        match self {
            Self::CreditDecision(decision) => decision.nonce,
            Self::Guarantee(guarantee) => guarantee.nonce,
        }
    }

    pub fn valid_until(&self) -> u64 {
        match self {
            Self::CreditDecision(decision) => decision.valid_until,
            Self::Guarantee(guarantee) => guarantee.valid_until,
        }
    }

    pub fn statement(&self) -> Result<Commitment, AethelError> {
        Ok(match self {
            Self::CreditDecision(decision) => decision.statement()?,
            Self::Guarantee(guarantee) => guarantee.statement()?,
        })
    }

    pub fn action_digest(&self) -> Commitment {
        let domain = match self {
            Self::CreditDecision(_) => CREDIT_DECISION_ACTION_DOMAIN,
            Self::Guarantee(_) => GUARANTEE_ACTION_DOMAIN,
        };
        Sha256::digest(domain).into()
    }

    /// Exact DeKYX context the holder must present against for this artifact
    /// on this series. The scope is the anonymous line (`request_id`).
    pub fn presentation_context(
        &self,
        series: &ReceivableSeries,
    ) -> Result<PresentationContext, AethelError> {
        if series.series_id != self.series_id() {
            return Err(AethelError::MismatchedArtifact);
        }
        Ok(PresentationContext {
            scope_digest: self.request_id(),
            audience_digest: series.aethel_domain_id,
            action_digest: self.action_digest(),
            request_digest: self.statement()?,
            challenge_nonce: self.nonce(),
            valid_until: self.valid_until(),
        })
    }

    pub(crate) fn eligibility_request(
        &self,
        series: &ReceivableSeries,
        issuer: &IssuerDefinition,
    ) -> Result<AethelEligibilityRequest, AethelError> {
        let context = self.presentation_context(series)?;
        Ok(AethelEligibilityRequest {
            request_id: context.scope_digest,
            issuer_provider_id: issuer.issuer_id,
            issuer_key_epoch: issuer.key_epoch,
            issuer_namespace_digest: issuer.namespace_digest,
            subject_kind: series.policy.subject_kind,
            policy_digest: series.policy.eligibility_policy_digest,
            required_qualifications: series.policy.required_qualifications.clone(),
            audience_digest: context.audience_digest,
            action_digest: context.action_digest,
            artifact_digest: context.request_digest,
            challenge_nonce: context.challenge_nonce,
            valid_until: context.valid_until,
        })
    }
}

/// Shape check for a stored binding. Content is DeKYX's responsibility; this
/// only refuses records that could not have come from a verification.
pub(crate) fn binding_is_well_formed(binding: &ConfidentialSubjectBinding) -> bool {
    ![
        binding.request_id,
        binding.issuer_provider_id,
        binding.issuer_namespace_digest,
        binding.subject_commitment,
        binding.scope_digest,
        binding.policy_digest,
        binding.subject_nullifier,
        binding.proof_digest,
        binding.subject_line_id,
    ]
    .contains(&ZERO)
        && binding.scope_digest == binding.request_id
        && binding.issuer_key_epoch != 0
        && binding.valid_until != 0
}
