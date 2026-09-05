//! Aethel adapter for DeCCP-backed guarantees.
//!
//! Aethel continues to own stream and receivable meaning. DeCCP owns capacity,
//! reservation, binding, claim consumption, and default-risk state. DeFMI owns
//! the referenced facility hold and final settlement receipt.

use deccp_core::{
    confidential_guarantee_claim_context, confidential_guarantee_release_context, ClearingBook,
    ConfidentialGuaranteeClaimRequest, ConfidentialGuaranteeReleaseRequest,
    ConfidentialGuaranteeReservation, DeCcpError, DeFmiPort, DefmiSettlementReceipt, Digest32,
    GuaranteeHoldStatus, Identifier,
};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AethelLossLayer {
    FirstLoss,
    PariPassu,
    Excess,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AethelGuaranteeOffer {
    pub operation_id: Identifier,
    pub guarantee_id: Identifier,
    pub request_id: Identifier,
    pub provider_id: Identifier,
    pub series_id: Identifier,
    pub stream_state_version: u64,
    pub stream_state_root: Digest32,
    pub credit_decision_id: Option<Identifier>,
    pub deccp_facility_id: Identifier,
    pub deccp_expected_sequence: u64,
    pub deccp_expected_state_digest: Digest32,
    pub deccp_after_state_digest: Digest32,
    pub deccp_hold_id: Identifier,
    pub defmi_facility_id: Identifier,
    pub defmi_hold_id: Identifier,
    pub coverage_commitment: Digest32,
    pub beneficiary_subject_line_id: Digest32,
    pub loss_layer: AethelLossLayer,
    pub guarantee_terms_digest: Digest32,
    pub claim_policy_digest: Digest32,
    pub relation_proof_digest: Digest32,
    pub valid_until: u64,
    pub nonce: Identifier,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AethelGuaranteeBinding {
    pub guarantee_id: Identifier,
    pub request_id: Identifier,
    pub provider_id: Identifier,
    pub series_id: Identifier,
    pub stream_state_version: u64,
    pub stream_state_root: Digest32,
    pub credit_decision_id: Option<Identifier>,
    pub deccp_facility_id: Identifier,
    pub deccp_hold_id: Identifier,
    pub defmi_facility_id: Identifier,
    pub defmi_hold_id: Identifier,
    pub coverage_commitment: Digest32,
    pub loss_layer: AethelLossLayer,
    pub guarantee_terms_digest: Digest32,
    pub claim_policy_digest: Digest32,
    pub relation_proof_digest: Digest32,
    pub valid_until: u64,
    pub nonce: Identifier,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AethelGuaranteeClaim {
    pub operation_id: Identifier,
    pub issuance_id: Identifier,
    pub default_event_digest: Digest32,
    pub deccp_expected_sequence: u64,
    pub deccp_expected_state_digest: Digest32,
    pub deccp_after_state_digest: Digest32,
    pub transition_proof_digest: Digest32,
    pub receipt: DefmiSettlementReceipt,
}

/// Withdrawal or expiry of an Aethel guarantee before it is claimed. Like a
/// claim, it advances the hidden facility state only through a DeFMI-verified
/// transition and receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AethelGuaranteeRelease {
    pub operation_id: Identifier,
    pub deccp_expected_sequence: u64,
    pub deccp_expected_state_digest: Digest32,
    pub deccp_after_state_digest: Digest32,
    pub transition_proof_digest: Digest32,
    pub receipt: DefmiSettlementReceipt,
}

pub struct AethelDeCcpAdapter;

impl AethelDeCcpAdapter {
    pub fn reserve<P: DeFmiPort>(
        book: &mut ClearingBook,
        offer: AethelGuaranteeOffer,
        defmi: &P,
        now: u64,
    ) -> Result<AethelGuaranteeBinding, DeCcpError> {
        let facility = book
            .confidential_guarantee_facility(&offer.deccp_facility_id)
            .ok_or(DeCcpError::UnknownGuaranteeFacility)?;
        if facility.guarantor_id != offer.provider_id
            || facility.beneficiary_subject_line_id != offer.beneficiary_subject_line_id
            || facility.defmi_facility_id != offer.defmi_facility_id
            || facility.policy_digest != offer.claim_policy_digest
            || offer.credit_decision_id == Some([0; 32])
            || [
                offer.guarantee_id,
                offer.request_id,
                offer.series_id,
                offer.stream_state_root,
                offer.coverage_commitment,
                offer.guarantee_terms_digest,
                offer.nonce,
            ]
            .contains(&[0; 32])
            || offer.stream_state_version == 0
        {
            return Err(DeCcpError::InvalidGuaranteeReservation);
        }
        let purpose_digest = aethel_guarantee_purpose(&offer);
        let hold = book.reserve_confidential_guarantee(
            ConfidentialGuaranteeReservation {
                operation_id: offer.operation_id,
                hold_id: offer.deccp_hold_id,
                facility_id: offer.deccp_facility_id,
                purpose_digest,
                coverage_commitment: offer.coverage_commitment,
                defmi_hold_id: offer.defmi_hold_id,
                relation_proof_digest: offer.relation_proof_digest,
                expected_facility_state_digest: offer.deccp_expected_state_digest,
                after_facility_state_digest: offer.deccp_after_state_digest,
                expected_facility_sequence: offer.deccp_expected_sequence,
                valid_until: offer.valid_until,
            },
            defmi,
            now,
        )?;
        if hold.status != GuaranteeHoldStatus::Reserved {
            return Err(DeCcpError::InvalidState);
        }
        Ok(AethelGuaranteeBinding {
            guarantee_id: offer.guarantee_id,
            request_id: offer.request_id,
            provider_id: offer.provider_id,
            series_id: offer.series_id,
            stream_state_version: offer.stream_state_version,
            stream_state_root: offer.stream_state_root,
            credit_decision_id: offer.credit_decision_id,
            deccp_facility_id: offer.deccp_facility_id,
            deccp_hold_id: offer.deccp_hold_id,
            defmi_facility_id: offer.defmi_facility_id,
            defmi_hold_id: offer.defmi_hold_id,
            coverage_commitment: offer.coverage_commitment,
            loss_layer: offer.loss_layer,
            guarantee_terms_digest: offer.guarantee_terms_digest,
            claim_policy_digest: offer.claim_policy_digest,
            relation_proof_digest: offer.relation_proof_digest,
            valid_until: offer.valid_until,
            nonce: offer.nonce,
        })
    }

    pub fn bind_issuance(
        book: &mut ClearingBook,
        operation_id: Identifier,
        binding: &AethelGuaranteeBinding,
        issuance_id: Identifier,
        now: u64,
    ) -> Result<(), DeCcpError> {
        book.bind_confidential_guarantee(operation_id, binding.deccp_hold_id, issuance_id, now)
    }

    pub fn claim<P: DeFmiPort>(
        book: &mut ClearingBook,
        binding: &AethelGuaranteeBinding,
        claim: AethelGuaranteeClaim,
        defmi: &P,
        now: u64,
    ) -> Result<(), DeCcpError> {
        book.consume_confidential_guarantee(Self::claim_request(binding, claim), defmi, now)
    }

    pub fn release<P: DeFmiPort>(
        book: &mut ClearingBook,
        binding: &AethelGuaranteeBinding,
        release: AethelGuaranteeRelease,
        defmi: &P,
        now: u64,
    ) -> Result<(), DeCcpError> {
        book.release_confidential_guarantee(Self::release_request(binding, release), defmi, now)
    }

    /// Exact DeFMI settlement context that a release receipt must bind.
    pub fn release_context(
        binding: &AethelGuaranteeBinding,
        release: &AethelGuaranteeRelease,
    ) -> Digest32 {
        confidential_guarantee_release_context(&Self::release_request(binding, release.clone()))
    }

    fn release_request(
        binding: &AethelGuaranteeBinding,
        release: AethelGuaranteeRelease,
    ) -> ConfidentialGuaranteeReleaseRequest {
        ConfidentialGuaranteeReleaseRequest {
            operation_id: release.operation_id,
            hold_id: binding.deccp_hold_id,
            expected_facility_state_digest: release.deccp_expected_state_digest,
            after_facility_state_digest: release.deccp_after_state_digest,
            expected_facility_sequence: release.deccp_expected_sequence,
            transition_proof_digest: release.transition_proof_digest,
            receipt: release.receipt,
        }
    }

    /// Exact DeFMI/zkPI settlement context that a claim receipt must bind.
    pub fn claim_context(
        binding: &AethelGuaranteeBinding,
        claim: &AethelGuaranteeClaim,
    ) -> Digest32 {
        confidential_guarantee_claim_context(&Self::claim_request(binding, claim.clone()))
    }

    fn claim_request(
        binding: &AethelGuaranteeBinding,
        claim: AethelGuaranteeClaim,
    ) -> ConfidentialGuaranteeClaimRequest {
        ConfidentialGuaranteeClaimRequest {
            operation_id: claim.operation_id,
            hold_id: binding.deccp_hold_id,
            exposure_id: claim.issuance_id,
            default_event_digest: claim.default_event_digest,
            expected_facility_state_digest: claim.deccp_expected_state_digest,
            after_facility_state_digest: claim.deccp_after_state_digest,
            expected_facility_sequence: claim.deccp_expected_sequence,
            transition_proof_digest: claim.transition_proof_digest,
            receipt: claim.receipt,
        }
    }
}

fn aethel_guarantee_purpose(offer: &AethelGuaranteeOffer) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(b"DECCP:AETHEL-GUARANTEE-PURPOSE:v1");
    hash.update(offer.guarantee_id);
    hash.update(offer.request_id);
    hash.update(offer.series_id);
    hash.update(offer.stream_state_version.to_be_bytes());
    hash.update(offer.stream_state_root);
    hash.update(offer.coverage_commitment);
    hash.update([match offer.loss_layer {
        AethelLossLayer::FirstLoss => 1,
        AethelLossLayer::PariPassu => 2,
        AethelLossLayer::Excess => 3,
    }]);
    hash.update(offer.guarantee_terms_digest);
    hash.update(offer.claim_policy_digest);
    hash.finalize().into()
}
