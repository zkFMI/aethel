//! One receivable, end to end across the module crates:
//! signed payment stream -> verified provider credit artifact -> receivable
//! issuance -> tokenization supply intents -> distribution settlement context
//! -> obligation-wallet queue and receipt reconciliation -> servicing payment
//! and default evidence -> default recorded in the authoritative book.
//!
//! Along the way the test pins the boundaries: balances live only behind the
//! DeFMI-facing ledger port, a provider cannot use a capability it was not
//! registered for, duplicate queue delivery is idempotent, supply cannot exceed
//! the bound authorization, and a default nobody's evidence supports, or that
//! the issuer or creditor signs themselves, is refused.

use std::collections::{BTreeMap, BTreeSet};

use aethel::prelude::*;
use aethel::protocol::dekyx_core::SubjectKind;
use aethel::servicing::DueInstallment;
use aethel::tokenization::{LedgerRejection, RedemptionCondition, SupplyChange, TokenSeriesStatus};
use aethel::types::id_key;
use ed25519_dalek::SigningKey;
use zkfmi_crypto::{
    backend::{Ed25519Signer, MlDsa65Signer},
    hybrid::signature::HybridSigner,
    key::{KeyId, KeyPurpose, KeyRecord, ParticipantId},
    suite::{Suite, SuiteId},
    traits::Signer as _,
};

fn sign_artifact<A: aethel_provider_sdk::SignedArtifact>(
    artifact: &mut A,
    key: &SigningKey,
) -> Result<[u8; 32], aethel_provider_sdk::ProviderError> {
    let participant = [artifact.provider_id()[0] + 40; 32];
    aethel_provider_sdk::sign_artifact(
        artifact,
        &aethel_provider_sdk::test_support::signer(key),
        &aethel_provider_sdk::test_support::key_record(key, participant, 1),
    )
}

fn id(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&id(seed))
}

fn obligation_signer() -> HybridSigner {
    HybridSigner::new(
        Ed25519Signer::from_seed(&id(21)),
        MlDsa65Signer::from_seed(&id(121)),
    )
}

fn obligation_key(signer: &HybridSigner) -> KeyRecord {
    KeyRecord {
        participant_id: ParticipantId::new(id_key(&id(21))).unwrap(),
        key_id: KeyId::new("aethel-obligor-payment-e2e-v1").unwrap(),
        suite: Suite::new(SuiteId::Ed25519MlDsa65),
        key_version: 1,
        purpose: KeyPurpose::SettlementInstruction,
        public_key: signer.public_key(),
        not_before: 1,
        not_after: 50_001,
        revoked_at: None,
        rotation_proof: None,
        dekyx_binding: None,
    }
}

const ATTESTOR: u8 = 1;
const ASSESSOR: u8 = 2;
const SERVICER: u8 = 5;
const ISSUER_KEY: u8 = 9;

fn provider(byte: u8, capabilities: &[ProviderCapability]) -> RegisterProvider {
    RegisterProvider {
        operation_id: id(10 + byte),
        provider: ProviderDefinition {
            provider_id: id(byte),
            participant_id: id(byte + 40),
            capabilities: capabilities.iter().copied().collect::<BTreeSet<_>>(),
            public_key: key(100 + byte).verifying_key().to_bytes(),
            artifact_key: aethel_provider_sdk::test_support::key_record(
                &key(100 + byte),
                id(byte + 40),
                1,
            ),
            policy_registry_digest: id(byte + 80),
            defmi_guarantor_id: None,
            valid_from: 1,
            valid_until: 100_000,
            sequence: 0,
            status: ProviderStatus::Active,
            retired_keys: Vec::new(),
        },
    }
}

fn stream_state() -> StreamState {
    StreamState {
        stream_id: id(20),
        payer_commitment: id(21),
        payee_commitment: id(22),
        settlement_asset_id: id(23),
        source_domain_digest: id(24),
        terms_digest: id(25),
        event_root: id(26),
        accrued_commitment: id(27),
        paid_commitment: [0; 32],
        eligible_commitment: id(28),
        pledged_commitment: [0; 32],
        as_of: 40,
        version: 1,
        status: StreamStatus::Active,
    }
}

fn series() -> ReceivableSeries {
    ReceivableSeries {
        series_id: id(34),
        aethel_domain_id: id(39),
        stream_id: id(20),
        receivable_asset_id: id(35),
        issuer_participant_id: id(36),
        policy: SeriesPolicy {
            requires_credit_decision: true,
            requires_guarantee: false,
            requires_funding_reservation: false,
            requires_confidential_subject: false,
            subject_kind: SubjectKind::LegalEntity,
            required_qualifications: Vec::new(),
            accepted_issuer_namespace_digest: None,
            allow_secondary_transfer: true,
            eligibility_policy_digest: id(37),
            claim_policy_digest: id(38),
        },
        valid_from: 1,
        maturity: 5_000,
        sequence: 0,
        status: ReceivableStatus::Active,
    }
}

/// The test double for DeFMI's receivable-token ledger. It is the only place
/// in this test that holds a per-holder balance.
#[derive(Default)]
struct DefmiLedger {
    balances: BTreeMap<(String, String), u64>,
    sequence: u64,
    applied: BTreeSet<String>,
}

impl AssetLedgerPort for DefmiLedger {
    fn apply_supply_intent(
        &mut self,
        intent: &SupplyIntent,
    ) -> Result<SupplyReceipt, LedgerRejection> {
        assert!(
            self.applied.insert(id_key(&intent.intent_id)),
            "the ledger must never see the same intent twice"
        );
        let asset = id_key(&intent.receivable_asset_id);
        match &intent.change {
            SupplyChange::Mint {
                units,
                recipient_commitment,
                ..
            } => {
                *self
                    .balances
                    .entry((asset, id_key(recipient_commitment)))
                    .or_default() += units;
            }
            SupplyChange::Burn {
                units,
                holder_commitment,
                ..
            } => {
                let balance = self
                    .balances
                    .get_mut(&(asset, id_key(holder_commitment)))
                    .expect("burn from a holder");
                *balance -= units;
            }
        }
        self.sequence += 1;
        Ok(SupplyReceipt {
            intent_id: intent.intent_id,
            receipt_digest: intent.statement().unwrap(),
            ledger_sequence: self.sequence,
            finalized_at: 60,
        })
    }
}

fn json_keys(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, inner) in map {
                out.push(key.clone());
                json_keys(inner, out);
            }
        }
        serde_json::Value::Array(items) => items.iter().for_each(|item| json_keys(item, out)),
        _ => {}
    }
}

#[test]
fn a_receivable_flows_from_signed_stream_to_default_across_every_module() {
    // --- Aethel book: providers, stream, series ---------------------------
    let mut book = AethelBook::default();
    for (byte, capabilities) in [
        (ATTESTOR, vec![ProviderCapability::StreamAttestor]),
        (ASSESSOR, vec![ProviderCapability::CreditAssessor]),
        (SERVICER, vec![ProviderCapability::Servicer]),
    ] {
        book.register_provider(provider(byte, &capabilities), 10)
            .unwrap();
    }

    let mut registration = RegisterStream {
        operation_id: id(30),
        attestor_provider_id: id(ATTESTOR),
        state: stream_state(),
        source_evidence_digest: id(31),
        relation_proof_digest: id(32),
        signature: Vec::new(),
    };
    // A provider cannot exercise a capability it was not registered for:
    // the credit assessor signs the stream registration.
    sign_artifact(&mut registration, &key(100 + ASSESSOR)).unwrap();
    registration.attestor_provider_id = id(ASSESSOR);
    assert_eq!(
        book.register_stream(registration.clone(), 40),
        Err(AethelError::MissingProviderCapability)
    );
    assert_eq!(
        book.verify_artifact(&registration, 40),
        Err(ProviderError::MissingProviderCapability)
    );
    registration.attestor_provider_id = id(ATTESTOR);
    sign_artifact(&mut registration, &key(100 + ATTESTOR)).unwrap();
    book.register_stream(registration, 40).unwrap();
    book.register_series(
        RegisterSeries {
            operation_id: id(33),
            series: series(),
        },
        40,
    )
    .unwrap();

    // --- Verified provider credit artifact --------------------------------
    let stream_root = book.stream(&id(20)).unwrap().state.root().unwrap();
    let mut decision = CreditDecision {
        operation_id: id(51),
        decision_id: id(52),
        request_id: id(50),
        provider_id: id(ASSESSOR),
        series_id: id(34),
        stream_state_version: 1,
        stream_state_root: stream_root,
        model_digest: id(53),
        policy_digest: id(54),
        decision_terms_commitment: id(55),
        relation_proof_digest: id(56),
        valid_until: 4_000,
        nonce: id(57),
        signature: Vec::new(),
    };
    sign_artifact(&mut decision, &key(100 + ASSESSOR)).unwrap();
    book.record_credit_decision(decision, 45).unwrap();

    // --- Receivable issuance authorization -------------------------------
    let issuance = ReceivableIssuance {
        operation_id: id(90),
        issuance_id: id(91),
        request_id: id(50),
        series_id: id(34),
        note_id: id(92),
        owner_commitment: id(36),
        face_value_commitment: id(94),
        before_stream_state_version: 1,
        before_stream_state_root: stream_root,
        after_pledged_commitment: id(95),
        allocation_nullifier: id(96),
        credit_decision_id: Some(id(52)),
        guarantee_id: None,
        funding_quote_id: None,
        relation_proof_digest: id(97),
        zkpi_digest: id(98),
        issued_at: 50,
    };
    book.issue_receivable(issuance.clone(), 50).unwrap();
    assert_eq!(book.stream(&id(20)).unwrap().state.version, 2);
    let recorded_series = book.series.get(&id_key(&id(34))).unwrap().clone();

    // --- Tokenization supply intents --------------------------------------
    let mut tokens = TokenizationBook::default();
    tokens
        .register_token_series(
            RegisterTokenSeries {
                operation_id: id(61),
                token_series: TokenSeries {
                    token_series_id: id(60),
                    series_id: id(34),
                    receivable_asset_id: id(35),
                    aethel_domain_id: id(39),
                    issuer_participant_id: id(36),
                    units_per_receivable: 100,
                    issuance_cap_units: 1_000,
                    tranches: Vec::new(),
                    transfer_restriction: TransferRestriction::Unrestricted,
                    redemption: vec![RedemptionCondition::StreamClosed],
                    valid_from: 1,
                    maturity: 5_000,
                    status: TokenSeriesStatus::Open,
                },
            },
            &recorded_series,
            50,
        )
        .unwrap();
    tokens
        .authorize_issuance(
            IssuanceAuthorization {
                operation_id: id(70),
                issuance_id: id(91),
                token_series_id: id(60),
                series_id: id(34),
                note_id: id(92),
                face_value_commitment: id(94),
                authorized_units: 100,
                authorization_digest: issuance.zkpi_digest,
                authorized_at: 50,
            },
            &issuance,
            50,
        )
        .unwrap();
    let holder_a = id(200);
    let holder_b = id(201);
    let mut ledger = DefmiLedger::default();
    for (operation, intent, units, recipient) in
        [(1u8, 101u8, 60u64, holder_a), (2, 102, 40, holder_b)]
    {
        let intent = tokens
            .mint(
                MintRequest {
                    operation_id: id(operation),
                    intent_id: id(intent),
                    issuance_id: id(91),
                    units,
                    recipient_commitment: recipient,
                    tranche_id: None,
                },
                55,
            )
            .unwrap();
        let receipt = tokens.submit(&intent.intent_id, &mut ledger).unwrap();
        // Re-submission is idempotent: same receipt, ledger untouched.
        assert_eq!(
            tokens.submit(&intent.intent_id, &mut ledger).unwrap(),
            receipt
        );
    }
    // Supply cannot exceed the bound receivable authorization.
    assert_eq!(
        tokens.mint(
            MintRequest {
                operation_id: id(3),
                intent_id: id(103),
                issuance_id: id(91),
                units: 1,
                recipient_commitment: holder_a,
                tranche_id: None,
            },
            56,
        ),
        Err(TokenizationError::SupplyExceedsAuthorization)
    );
    assert_eq!(tokens.outstanding_units(&id(60)), 100);
    // Balances exist only behind the DeFMI-facing port.
    let asset = id_key(&id(35));
    assert_eq!(ledger.balances[&(asset.clone(), id_key(&holder_a))], 60);
    assert_eq!(ledger.balances[&(asset, id_key(&holder_b))], 40);
    let mut keys = Vec::new();
    json_keys(&serde_json::to_value(&tokens).unwrap(), &mut keys);
    for holder in [holder_a, holder_b] {
        assert!(!keys.contains(&id_key(&holder)));
    }
    assert!(keys.iter().all(|key| !key.contains("balance")));
    tokens.validate().unwrap();

    // --- Distribution settlement context ----------------------------------
    let token_series = tokens.token_series(&id(60)).unwrap().clone();
    let mut distribution = DistributionBook::default();
    let handoff = distribution
        .admit(
            CirculationRequest {
                request_id: id(120),
                operation_id: id(121),
                token_series_id: id(60),
                series_id: id(34),
                issuance_id: id(91),
                receivable_asset_id: id(35),
                cash_asset_id: id(23),
                units: 30,
                side: Side::Sell,
                initiator_commitment: holder_a,
                counterparty_commitment: None,
                limit_price_commitment: None,
                venue: Venue::Qomm,
                eligibility_attestation_digest: None,
                valid_until: 500,
            },
            &token_series,
            60,
        )
        .unwrap();
    assert_eq!(handoff.venue, Venue::Qomm);
    let context = distribution
        .accept_fill(
            VenueFill {
                fill_id: id(122),
                request_id: id(120),
                venue: Venue::Qomm,
                units: 30,
                counterparty_commitment: id(202),
                price_commitment: id(123),
                venue_evidence_digest: id(124),
                filled_at: 70,
            },
            70,
        )
        .unwrap();
    assert_eq!(context.seller_commitment, holder_a);
    assert_eq!(context.issuance_id, issuance.issuance_id);
    let context_statement = context.statement().unwrap();
    assert_ne!(context_statement, ZERO);
    distribution
        .record_outcome(
            &context.context_id,
            SettlementOutcome::Settled {
                receipt_digest: context_statement,
                finalized_at: 80,
            },
        )
        .unwrap();
    distribution.validate().unwrap();

    // --- Obligation wallet: queue and reconciliation ----------------------
    let mut wallet = ObligationWallet::new(
        PaymentSchedule {
            stream_id: id(20),
            obligor_commitment: id(21),
            payee_commitment: id(22),
            settlement_asset_id: id(23),
            installments: (1..=3)
                .map(|sequence| aethel::obligation_wallet::Installment {
                    sequence,
                    due_at: 1_000 * sequence,
                    units: 40,
                })
                .collect(),
        },
        RetryPolicy {
            max_attempts: 3,
            base_delay_seconds: 10,
            max_delay_seconds: 60,
        },
    )
    .unwrap();
    let obligor_key = obligation_signer();
    wallet
        .add_authorization(
            PreAuthorization {
                authorization_id: id(130),
                stream_id: id(20),
                obligor_commitment: id(21),
                payee_commitment: id(22),
                settlement_asset_id: id(23),
                payment_key: obligation_key(&obligor_key),
                per_payment_ceiling: 40,
                period_ceiling: 120,
                period_seconds: 10_000,
                valid_from: 1,
                valid_until: 50_000,
            },
            900,
        )
        .unwrap();
    let signed = wallet
        .prepare(1, &id(130), id(131), 900)
        .unwrap()
        .sign(&obligor_key)
        .unwrap();
    assert_eq!(
        wallet.enqueue(signed.clone(), 900),
        Ok(EnqueueOutcome::Accepted)
    );
    // Duplicate queue delivery is idempotent.
    assert_eq!(
        wallet.enqueue(signed.clone(), 901),
        Ok(EnqueueOutcome::Duplicate)
    );
    assert_eq!(wallet.queue.len(), 1);
    assert_eq!(wallet.mark_in_flight(&id(131), 905), Ok(1));
    assert_eq!(wallet.settled_units().unwrap(), 0);
    let receipt = SettlementReceipt {
        payment_id: id(131),
        receipt_digest: signed.payment.statement().unwrap(),
        settled_units: 40,
        finalized_at: 950,
    };
    assert_eq!(
        wallet.reconcile(receipt.clone()),
        Ok(Reconciliation::Matched)
    );
    assert_eq!(
        wallet.reconcile(receipt.clone()),
        Ok(Reconciliation::AlreadyReconciled)
    );
    assert_eq!(wallet.settled_units().unwrap(), 40);
    let restored = ObligationWallet::restore(&wallet.snapshot().unwrap()).unwrap();
    assert_eq!(restored, wallet);

    // --- Servicing: payment evidence, then default evidence ---------------
    let mut servicing = ServicingBook::new(ServicingTerms {
        stream_id: id(20),
        schedule: (1..=3)
            .map(|sequence| DueInstallment {
                sequence,
                due_at: 1_000 * sequence,
                units: 40,
            })
            .collect(),
        grace_seconds: 100,
        cure_window_seconds: 500,
        default_after_missed: 2,
    })
    .unwrap();
    let mut paid = PaymentEvidence {
        evidence_id: id(140),
        operation_id: id(141),
        provider_id: id(SERVICER),
        stream_id: id(20),
        installment_sequence: 1,
        paid_units: receipt.settled_units,
        observed_at: 960,
        source_evidence_digest: receipt.receipt_digest,
        signature: Vec::new(),
    };
    sign_artifact(&mut paid, &key(100 + SERVICER)).unwrap();
    servicing.record_payment_evidence(paid, &book, 961).unwrap();
    // A credit provider's signature is an opinion, not payment evidence.
    let mut opinion = PaymentEvidence {
        evidence_id: id(142),
        operation_id: id(143),
        provider_id: id(ASSESSOR),
        stream_id: id(20),
        installment_sequence: 2,
        paid_units: 40,
        observed_at: 1_900,
        source_evidence_digest: id(144),
        signature: Vec::new(),
    };
    sign_artifact(&mut opinion, &key(100 + ASSESSOR)).unwrap();
    assert_eq!(
        servicing.record_payment_evidence(opinion, &book, 1_901),
        Err(ServicingError::NotAnObserver)
    );
    assert_eq!(servicing.evaluate(1_950), &ServicingStatus::Performing);
    // Installments 2 and 3 go unpaid past grace and cure.
    assert_eq!(
        servicing.default_evidence(3_000),
        Err(ServicingError::DefaultUnsupported)
    );
    let evidence = servicing.default_evidence(3_200).unwrap();
    assert_eq!(evidence.missed_sequences, vec![2, 3]);

    // The attestor moves the stream to Defaulted, as its source shows.
    let current = book.stream(&id(20)).unwrap().state.clone();
    let mut defaulted = current.clone();
    defaulted.version += 1;
    defaulted.as_of = 3_210;
    defaulted.status = StreamStatus::Defaulted;
    let mut transition = StreamTransition {
        operation_id: id(160),
        attestor_provider_id: id(ATTESTOR),
        before_state_root: current.root().unwrap(),
        after_state: defaulted,
        source_evidence_digest: id(161),
        relation_proof_digest: id(162),
        signature: Vec::new(),
    };
    sign_artifact(&mut transition, &key(100 + ATTESTOR)).unwrap();
    book.transition_stream(transition, 3_210).unwrap();
    let defaulted_state = book.stream(&id(20)).unwrap().state.clone();

    let draft = |provider: u8, book: &ServicingBook| {
        book.draft_default_attestation(
            id(170),
            id(171),
            id(provider),
            defaulted_state.version,
            defaulted_state.root().unwrap(),
            3_220,
        )
        .unwrap()
    };
    // The issuer signs the default itself: not a registered servicer.
    let mut self_declared = draft(ISSUER_KEY, &servicing);
    sign_artifact(&mut self_declared, &key(100 + ISSUER_KEY)).unwrap();
    assert_eq!(
        servicing.accept_default_attestation(self_declared.clone(), &book, 3_221),
        Err(ServicingError::NotAServicer)
    );
    assert_eq!(
        book.record_default(self_declared, 3_221),
        Err(AethelError::UnknownProvider)
    );
    // The creditor signs it: registered, but not as a servicer.
    let mut creditor_declared = draft(ASSESSOR, &servicing);
    sign_artifact(&mut creditor_declared, &key(100 + ASSESSOR)).unwrap();
    assert_eq!(
        servicing.accept_default_attestation(creditor_declared.clone(), &book, 3_221),
        Err(ServicingError::NotAServicer)
    );
    assert_eq!(
        book.record_default(creditor_declared, 3_221),
        Err(AethelError::MissingProviderCapability)
    );
    // The servicer signs an event the evidence does not describe.
    let mut unsupported = draft(SERVICER, &servicing);
    unsupported.event_digest = id(199);
    sign_artifact(&mut unsupported, &key(100 + SERVICER)).unwrap();
    assert_eq!(
        servicing.accept_default_attestation(unsupported, &book, 3_221),
        Err(ServicingError::UnsupportedDefault)
    );
    // The servicer attests exactly the derived evidence; servicing accepts
    // it and the authoritative book records it.
    let mut genuine = draft(SERVICER, &servicing);
    sign_artifact(&mut genuine, &key(100 + SERVICER)).unwrap();
    servicing
        .accept_default_attestation(genuine.clone(), &book, 3_221)
        .unwrap();
    book.record_default(genuine, 3_221).unwrap();
    assert_eq!(
        servicing.status,
        ServicingStatus::Defaulted {
            attestation_id: id(171)
        }
    );
    assert!(book.default_attestations.contains_key(&id_key(&id(171))));

    book.validate().unwrap();
    servicing.validate().unwrap();
    assert_ne!(book.root().unwrap(), ZERO);
    assert_ne!(tokens.root().unwrap(), ZERO);
    assert_ne!(distribution.root().unwrap(), ZERO);
    assert_ne!(wallet.root().unwrap(), ZERO);
    assert_ne!(servicing.root().unwrap(), ZERO);
}
