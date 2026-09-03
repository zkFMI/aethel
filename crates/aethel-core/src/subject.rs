//! Aethel's thin adapter onto DeKYX.
//!
//! Aethel keeps only what a receivable line needs: which provider vouches for
//! a DeKYX issuer key, which provider artifact a presentation is bound to, and
//! the DeKYX-produced binding stored beside that artifact. Issuer trust, key
//! epochs, credential signatures, qualifications, revocation, and the
//! zero-knowledge presentation belong to DeKYX and are not re-implemented here.

use dekyx_aethel::{AethelEligibilityRequest, AethelSubjectBinding};
use dekyx_core::{IssuerDefinition, PresentationContext, RevocationStatusList};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    digest, AethelError, Commitment, CreditDecision, GuaranteeCommitment, Identifier,
    ReceivableSeries, ZERO,
};

const CREDENTIAL_ISSUER_DOMAIN: &[u8] = b"AETHEL:CREDENTIAL-ISSUER:v1";
const CREDENTIAL_STATUS_DOMAIN: &[u8] = b"AETHEL:CREDENTIAL-STATUS:v1";
const CREDIT_DECISION_ACTION_DOMAIN: &[u8] = b"AETHEL:SUBJECT-ACTION:CREDIT-DECISION:v1";
const GUARANTEE_ACTION_DOMAIN: &[u8] = b"AETHEL:SUBJECT-ACTION:GUARANTEE:v1";

/// The record Aethel stores for an anonymous line. It is produced only by
/// DeKYX verification; Aethel never constructs one from unverified input.
pub type ConfidentialSubjectBinding = AethelSubjectBinding;

/// A credential-issuer provider vouching for one DeKYX issuer key epoch.
///
/// The DeKYX issuer id is the Aethel provider id, so a credential names its
/// vouching provider directly. The DeKYX signing key is separate from the
/// provider's artifact key and rotates independently of it: a rotation is a
/// second registration by the same provider with a higher epoch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterCredentialIssuer {
    pub operation_id: Identifier,
    pub provider_id: Identifier,
    pub issuer: IssuerDefinition,
    /// `None` for the first key epoch. For a rotation, the last instant at
    /// which credentials signed by earlier epochs stay acceptable; a value
    /// before their `valid_from` retires them immediately, which is the
    /// key-compromise path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_epochs_valid_until: Option<u64>,
    pub signature: Vec<u8>,
}

impl RegisterCredentialIssuer {
    pub fn statement(&self) -> Result<Commitment, AethelError> {
        if self.operation_id == ZERO || self.issuer.issuer_id != self.provider_id {
            return Err(AethelError::InvalidCredentialIssuer);
        }
        self.issuer.validate().map_err(AethelError::Credential)?;
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        digest(CREDENTIAL_ISSUER_DOMAIN, &unsigned)
    }
}

/// An issuer-signed revocation status list for one DeKYX issuer key epoch.
/// Its authenticity is the issuer key's; Aethel adds only replay protection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublishCredentialStatus {
    pub operation_id: Identifier,
    pub status_list: RevocationStatusList,
}

impl PublishCredentialStatus {
    pub fn statement(&self) -> Result<Commitment, AethelError> {
        if self.operation_id == ZERO {
            return Err(AethelError::InvalidCredentialStatus);
        }
        self.status_list
            .statement_digest()
            .map_err(AethelError::Credential)?;
        digest(CREDENTIAL_STATUS_DOMAIN, self)
    }
}

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
        match self {
            Self::CreditDecision(decision) => decision.statement(),
            Self::Guarantee(guarantee) => guarantee.statement(),
        }
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
