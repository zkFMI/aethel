use aethel_deccp::{
    AethelDeCcpAdapter, AethelGuaranteeClaim, AethelGuaranteeOffer, AethelGuaranteeRelease,
    AethelLossLayer,
};
use deccp_core::{
    confidential_guarantee_claim_context, confidential_guarantee_facility_approval_digest,
    AuthorityMember, AuthoritySet, CcpCapitalization, ClearingBook, CollateralLot,
    ConfidentialGuaranteeClaimRequest, ConfidentialGuaranteeFacility, ConfidentialGuaranteeHold,
    ConfidentialGuaranteeReleaseRequest, ConfidentialGuaranteeReservation, DeCcpError, DeFmiPort,
    DefmiSettlementReceipt, EligibilityAttestation, EligibilityPort, GuaranteeFacility,
    GuaranteeFacilityStatus, GuaranteeHoldStatus, GuaranteeReservation, ParticipantAdmission,
    QuorumApproval, VerifiedAdmission,
};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

fn id(byte: u8) -> [u8; 32] {
    [byte; 32]
}

struct Eligibility;

impl EligibilityPort for Eligibility {
    fn verify(
        &self,
        evidence: &EligibilityAttestation,
        _now: u64,
    ) -> Result<VerifiedAdmission, String> {
        Ok(VerifiedAdmission {
            provider_id: evidence.provider_id,
            subject_line_id: evidence.subject_line_id,
            policy_digest: evidence.policy_digest,
            evidence_digest: evidence.evidence_digest,
            valid_until: evidence.valid_until,
        })
    }
}

struct Defmi;

impl DeFmiPort for Defmi {
    fn verify_ccp_capital(
        &self,
        _capitalization: &CcpCapitalization,
        _now: u64,
    ) -> Result<(), String> {
        Ok(())
    }

    fn verify_default_fund(
        &self,
        _admission: &ParticipantAdmission,
        _now: u64,
    ) -> Result<(), String> {
        Ok(())
    }

    fn verify_collateral_lock(&self, _lot: &CollateralLot, _now: u64) -> Result<(), String> {
        Ok(())
    }

    fn verify_guarantee_facility(
        &self,
        _facility: &GuaranteeFacility,
        _now: u64,
    ) -> Result<(), String> {
        Ok(())
    }

    fn verify_guarantee_hold(
        &self,
        _reservation: &GuaranteeReservation,
        _now: u64,
    ) -> Result<(), String> {
        Ok(())
    }

    fn verify_confidential_guarantee_facility(
        &self,
        facility: &ConfidentialGuaranteeFacility,
        now: u64,
    ) -> Result<(), String> {
        (facility.valid_until >= now)
            .then_some(())
            .ok_or_else(|| "expired facility".into())
    }

    fn verify_confidential_guarantee_hold(
        &self,
        facility: &ConfidentialGuaranteeFacility,
        reservation: &ConfidentialGuaranteeReservation,
        now: u64,
    ) -> Result<(), String> {
        (reservation.valid_until >= now
            && reservation.expected_facility_state_digest == facility.latest_facility_state_digest)
            .then_some(())
            .ok_or_else(|| "wrong hold transition".into())
    }

    fn verify_confidential_guarantee_release(
        &self,
        _facility: &ConfidentialGuaranteeFacility,
        _hold: &ConfidentialGuaranteeHold,
        _request: &ConfidentialGuaranteeReleaseRequest,
        _now: u64,
    ) -> Result<(), String> {
        Ok(())
    }

    fn verify_confidential_guarantee_claim(
        &self,
        facility: &ConfidentialGuaranteeFacility,
        hold: &ConfidentialGuaranteeHold,
        request: &ConfidentialGuaranteeClaimRequest,
        now: u64,
    ) -> Result<(), String> {
        (hold.facility_id == facility.facility_id
            && request.expected_facility_state_digest == facility.latest_facility_state_digest
            && request.receipt.context_digest == confidential_guarantee_claim_context(request)
            && request.receipt.finalized_at <= now)
            .then_some(())
            .ok_or_else(|| "wrong claim transition".into())
    }

    fn verify_guarantee_release(
        &self,
        expected_context: &[u8; 32],
        receipt: &DefmiSettlementReceipt,
        now: u64,
    ) -> Result<(), String> {
        (&receipt.context_digest == expected_context && receipt.finalized_at <= now)
            .then_some(())
            .ok_or_else(|| "wrong release".into())
    }

    fn verify_settlement(
        &self,
        expected_context: &[u8; 32],
        receipt: &DefmiSettlementReceipt,
        now: u64,
    ) -> Result<(), String> {
        (&receipt.context_digest == expected_context && receipt.finalized_at <= now)
            .then_some(())
            .ok_or_else(|| "wrong settlement".into())
    }
}

#[test]
fn aethel_uses_deccp_hold_without_owning_guarantee_state() {
    let keys: Vec<_> = (1..=2)
        .map(|index| (id(index), SigningKey::generate(&mut OsRng)))
        .collect();
    let authorities = AuthoritySet {
        epoch: 1,
        threshold: 2,
        members: keys
            .iter()
            .map(|(member_id, key)| AuthorityMember {
                member_id: *member_id,
                public_key: key.verifying_key().to_bytes(),
            })
            .collect(),
    };
    let approve = |digest| {
        QuorumApproval::sign(
            1,
            digest,
            &[(keys[0].0, &keys[0].1), (keys[1].0, &keys[1].1)],
        )
    };
    let mut book = ClearingBook::new(
        authorities,
        CcpCapitalization {
            amount: 100,
            defmi_lock_id: id(8),
            proof_digest: id(9),
            valid_until: 1_000,
        },
        &Defmi,
        100,
    )
    .unwrap();
    let admission = ParticipantAdmission {
        operation_id: id(10),
        participant_id: id(20),
        settlement_participant_id: id(21),
        eligibility: EligibilityAttestation {
            provider_id: id(22),
            subject_line_id: id(23),
            policy_digest: id(24),
            evidence_digest: id(25),
            valid_until: 1_000,
        },
        default_fund_contribution: 10,
        default_fund_defmi_lock_id: id(26),
        default_fund_proof_digest: id(27),
        admitted_at: 100,
    };
    let admission_approval = approve(admission.statement_digest().unwrap());
    book.admit_participant(admission, &Eligibility, &admission_approval, &Defmi, 100)
        .unwrap();
    let facility = ConfidentialGuaranteeFacility {
        facility_id: id(30),
        guarantor_id: id(20),
        beneficiary_subject_line_id: id(31),
        settlement_asset_id: id(32),
        capacity_commitment: id(35),
        latest_facility_state_digest: id(36),
        defmi_facility_id: id(33),
        policy_digest: id(34),
        valid_until: 900,
        sequence: 0,
        status: GuaranteeFacilityStatus::Active,
    };
    let facility_approval = approve(confidential_guarantee_facility_approval_digest(
        &id(11),
        &facility,
    ));
    book.register_confidential_guarantee_facility(
        id(11),
        facility,
        &facility_approval,
        &Defmi,
        100,
    )
    .unwrap();
    let binding = AethelDeCcpAdapter::reserve(
        &mut book,
        AethelGuaranteeOffer {
            operation_id: id(12),
            guarantee_id: id(40),
            request_id: id(41),
            provider_id: id(20),
            series_id: id(42),
            stream_state_version: 1,
            stream_state_root: id(43),
            credit_decision_id: Some(id(44)),
            deccp_facility_id: id(30),
            deccp_expected_sequence: 0,
            deccp_expected_state_digest: id(36),
            deccp_after_state_digest: id(37),
            deccp_hold_id: id(45),
            defmi_facility_id: id(33),
            defmi_hold_id: id(46),
            coverage_commitment: id(47),
            beneficiary_subject_line_id: id(31),
            loss_layer: AethelLossLayer::FirstLoss,
            guarantee_terms_digest: id(48),
            claim_policy_digest: id(34),
            relation_proof_digest: id(49),
            valid_until: 800,
            nonce: id(50),
        },
        &Defmi,
        100,
    )
    .unwrap();
    AethelDeCcpAdapter::bind_issuance(&mut book, id(13), &binding, id(51), 110).unwrap();
    let mut claim = AethelGuaranteeClaim {
        operation_id: id(14),
        issuance_id: id(51),
        default_event_digest: id(52),
        deccp_expected_sequence: 1,
        deccp_expected_state_digest: id(37),
        deccp_after_state_digest: id(38),
        transition_proof_digest: id(39),
        receipt: DefmiSettlementReceipt {
            receipt_digest: id(53),
            context_digest: [0; 32],
            finalized_at: 120,
        },
    };
    claim.receipt.context_digest = AethelDeCcpAdapter::claim_context(&binding, &claim);
    AethelDeCcpAdapter::claim(&mut book, &binding, claim, &Defmi, 120).unwrap();
    let hold = book.confidential_guarantee_hold(&id(45)).unwrap();
    assert_eq!(hold.status, GuaranteeHoldStatus::Consumed);
    assert_eq!(hold.defmi_settlement_receipt, Some(id(53)));
    assert_eq!(hold.coverage_commitment, id(47));
    let facility = book.confidential_guarantee_facility(&id(30)).unwrap();
    assert_eq!(facility.latest_facility_state_digest, id(38));
    assert_eq!(facility.sequence, 2);
}

fn confidential_book() -> (ClearingBook, Vec<([u8; 32], SigningKey)>) {
    let keys: Vec<_> = (1..=2)
        .map(|index| (id(index), SigningKey::generate(&mut OsRng)))
        .collect();
    let authorities = AuthoritySet {
        epoch: 1,
        threshold: 2,
        members: keys
            .iter()
            .map(|(member_id, key)| AuthorityMember {
                member_id: *member_id,
                public_key: key.verifying_key().to_bytes(),
            })
            .collect(),
    };
    let approve = |digest| {
        QuorumApproval::sign(
            1,
            digest,
            &[(keys[0].0, &keys[0].1), (keys[1].0, &keys[1].1)],
        )
    };
    let mut book = ClearingBook::new(
        authorities,
        CcpCapitalization {
            amount: 100,
            defmi_lock_id: id(8),
            proof_digest: id(9),
            valid_until: 1_000,
        },
        &Defmi,
        100,
    )
    .unwrap();
    let admission = ParticipantAdmission {
        operation_id: id(10),
        participant_id: id(20),
        settlement_participant_id: id(21),
        eligibility: EligibilityAttestation {
            provider_id: id(22),
            subject_line_id: id(23),
            policy_digest: id(24),
            evidence_digest: id(25),
            valid_until: 1_000,
        },
        default_fund_contribution: 10,
        default_fund_defmi_lock_id: id(26),
        default_fund_proof_digest: id(27),
        admitted_at: 100,
    };
    let admission_approval = approve(admission.statement_digest().unwrap());
    book.admit_participant(admission, &Eligibility, &admission_approval, &Defmi, 100)
        .unwrap();
    let facility = ConfidentialGuaranteeFacility {
        facility_id: id(30),
        guarantor_id: id(20),
        beneficiary_subject_line_id: id(31),
        settlement_asset_id: id(32),
        capacity_commitment: id(35),
        latest_facility_state_digest: id(36),
        defmi_facility_id: id(33),
        policy_digest: id(34),
        valid_until: 900,
        sequence: 0,
        status: GuaranteeFacilityStatus::Active,
    };
    let facility_approval = approve(confidential_guarantee_facility_approval_digest(
        &id(11),
        &facility,
    ));
    book.register_confidential_guarantee_facility(
        id(11),
        facility,
        &facility_approval,
        &Defmi,
        100,
    )
    .unwrap();
    (book, keys)
}

fn offer() -> AethelGuaranteeOffer {
    AethelGuaranteeOffer {
        operation_id: id(12),
        guarantee_id: id(40),
        request_id: id(41),
        provider_id: id(20),
        series_id: id(42),
        stream_state_version: 1,
        stream_state_root: id(43),
        credit_decision_id: Some(id(44)),
        deccp_facility_id: id(30),
        deccp_expected_sequence: 0,
        deccp_expected_state_digest: id(36),
        deccp_after_state_digest: id(37),
        deccp_hold_id: id(45),
        defmi_facility_id: id(33),
        defmi_hold_id: id(46),
        coverage_commitment: id(47),
        beneficiary_subject_line_id: id(31),
        loss_layer: AethelLossLayer::FirstLoss,
        guarantee_terms_digest: id(48),
        claim_policy_digest: id(34),
        relation_proof_digest: id(49),
        valid_until: 800,
        nonce: id(50),
    }
}

#[test]
fn aethel_guarantee_path_carries_no_plaintext_amount_anywhere() {
    let (mut book, _) = confidential_book();
    let offer = offer();
    // The adapter's own request and record types name no amount at all.
    let offer_debug = format!("{offer:?}").to_ascii_lowercase();
    assert!(!offer_debug.contains("amount") && !offer_debug.contains("capacity"));
    let binding = AethelDeCcpAdapter::reserve(&mut book, offer, &Defmi, 100).unwrap();
    let binding_debug = format!("{binding:?}").to_ascii_lowercase();
    assert!(!binding_debug.contains("amount") && !binding_debug.contains("capacity"));

    // What DeCCP stores for the facility and the hold is commitments and
    // digests only; no integer amount, capacity, reserved, or consumed field.
    let hold = serde_json::to_value(book.confidential_guarantee_hold(&id(45)).unwrap()).unwrap();
    let facility =
        serde_json::to_value(book.confidential_guarantee_facility(&id(30)).unwrap()).unwrap();
    for value in [&hold, &facility] {
        let object = value.as_object().unwrap();
        assert!(object.keys().all(|key| {
            let key = key.to_ascii_lowercase();
            !key.contains("amount") && key != "capacity" && key != "reserved" && key != "consumed"
        }));
        assert!(object
            .values()
            .all(|field| !field.is_number() || field.is_u64()));
    }
    assert_eq!(
        hold["coverageCommitment"],
        serde_json::to_value(id(47)).unwrap()
    );
    assert_eq!(
        facility["capacityCommitment"],
        serde_json::to_value(id(35)).unwrap()
    );
    // The public-value facility path was never touched.
    assert!(book.guarantee_facility(&id(30)).is_none());
    assert!(book.guarantee_hold(&id(45)).is_none());
}

#[test]
fn aethel_release_returns_capacity_only_through_a_verified_transition() {
    let (mut book, _) = confidential_book();
    let binding = AethelDeCcpAdapter::reserve(&mut book, offer(), &Defmi, 100).unwrap();
    let mut release = AethelGuaranteeRelease {
        operation_id: id(60),
        deccp_expected_sequence: 1,
        deccp_expected_state_digest: id(37),
        deccp_after_state_digest: id(61),
        transition_proof_digest: id(62),
        receipt: DefmiSettlementReceipt {
            receipt_digest: id(63),
            context_digest: [0; 32],
            finalized_at: 110,
        },
    };
    // A receipt for another context is refused before any state changes.
    release.receipt.context_digest = id(64);
    assert_eq!(
        AethelDeCcpAdapter::release(&mut book, &binding, release.clone(), &Defmi, 110),
        Err(DeCcpError::ReplayOrStaleOperation)
    );
    assert_eq!(
        book.confidential_guarantee_hold(&id(45)).unwrap().status,
        GuaranteeHoldStatus::Reserved
    );
    release.receipt.context_digest = AethelDeCcpAdapter::release_context(&binding, &release);
    AethelDeCcpAdapter::release(&mut book, &binding, release.clone(), &Defmi, 110).unwrap();
    let hold = book.confidential_guarantee_hold(&id(45)).unwrap();
    assert_eq!(hold.status, GuaranteeHoldStatus::Released);
    assert_eq!(hold.defmi_settlement_receipt, Some(id(63)));
    let facility = book.confidential_guarantee_facility(&id(30)).unwrap();
    assert_eq!(facility.latest_facility_state_digest, id(61));
    assert_eq!(facility.sequence, 2);
    // A released hold cannot be bound or claimed afterwards.
    assert_eq!(
        AethelDeCcpAdapter::bind_issuance(&mut book, id(65), &binding, id(66), 120),
        Err(DeCcpError::GuaranteeHoldUnavailable)
    );
}
