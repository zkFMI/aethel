use std::collections::BTreeSet;

use aethel_core::dekyx_core::{
    AnonymousPresentation, Credential, CredentialIssuer, CredentialRequest, CredentialWitness,
    DeKyxError, IssuerDefinition, IssuerStatus, Qualification, SubjectKind,
};
use aethel_core::{
    AethelBook, AethelError, ConfidentialArtifact, CreditDecision, FundingQuote,
    GuaranteeCommitment, GuaranteeRelease, GuaranteeStatus, LossLayer, ProviderCapability,
    ProviderDefinition, ProviderStatus, PublishCredentialStatus, ReceivableIssuance,
    ReceivableSeries, ReceivableStatus, RegisterCredentialIssuer, RegisterProvider, RegisterSeries,
    RegisterStream, RotateProviderKey, SeriesPolicy, SetProviderStatus, StreamState, StreamStatus,
};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;

fn id(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn signer(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&id(seed))
}

fn provider(
    provider_id: u8,
    key: &SigningKey,
    capabilities: &[ProviderCapability],
    guarantor_id: Option<u8>,
) -> ProviderDefinition {
    ProviderDefinition {
        provider_id: id(provider_id),
        participant_id: id(provider_id + 40),
        capabilities: capabilities.iter().copied().collect::<BTreeSet<_>>(),
        public_key: key.verifying_key().to_bytes(),
        policy_registry_digest: id(provider_id + 80),
        defmi_guarantor_id: guarantor_id.map(id),
        valid_from: 1,
        valid_until: 2_000,
        sequence: 0,
        status: ProviderStatus::Active,
        retired_keys: Vec::new(),
    }
}

fn register_provider(book: &mut AethelBook, operation: u8, definition: ProviderDefinition) {
    book.register_provider(
        RegisterProvider {
            operation_id: id(operation),
            provider: definition,
        },
        10,
    )
    .unwrap();
}

fn initial_stream() -> StreamState {
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

fn register_stream(book: &mut AethelBook, attestor: &SigningKey) {
    let mut request = RegisterStream {
        operation_id: id(30),
        attestor_provider_id: id(1),
        state: initial_stream(),
        source_evidence_digest: id(31),
        relation_proof_digest: id(32),
        signature: Vec::new(),
    };
    request.signature = attestor
        .sign(&request.statement().unwrap())
        .to_bytes()
        .to_vec();
    book.register_stream(request, 40).unwrap();
}

fn register_series(book: &mut AethelBook, policy: SeriesPolicy) {
    book.register_series(
        RegisterSeries {
            operation_id: id(33),
            series: ReceivableSeries {
                series_id: id(34),
                aethel_domain_id: id(39),
                stream_id: id(20),
                receivable_asset_id: id(35),
                issuer_participant_id: id(36),
                policy,
                valid_from: 1,
                maturity: 1_000,
                sequence: 0,
                status: ReceivableStatus::Active,
            },
        },
        40,
    )
    .unwrap();
}

fn policy(credit: bool, guarantee: bool, funding: bool) -> SeriesPolicy {
    SeriesPolicy {
        requires_credit_decision: credit,
        requires_guarantee: guarantee,
        requires_funding_reservation: funding,
        requires_confidential_subject: false,
        subject_kind: SubjectKind::LegalEntity,
        required_qualifications: Vec::new(),
        accepted_issuer_namespace_digest: None,
        allow_secondary_transfer: true,
        eligibility_policy_digest: id(37),
        claim_policy_digest: id(38),
    }
}

fn issuance(
    book: &AethelBook,
    credit_decision_id: Option<[u8; 32]>,
    guarantee_id: Option<[u8; 32]>,
    funding_quote_id: Option<[u8; 32]>,
) -> ReceivableIssuance {
    let stream = &book.stream(&id(20)).unwrap().state;
    ReceivableIssuance {
        operation_id: id(90),
        issuance_id: id(91),
        request_id: id(50),
        series_id: id(34),
        note_id: id(92),
        owner_commitment: id(93),
        face_value_commitment: id(94),
        before_stream_state_version: stream.version,
        before_stream_state_root: stream.root().unwrap(),
        after_pledged_commitment: id(95),
        allocation_nullifier: id(96),
        credit_decision_id,
        guarantee_id,
        funding_quote_id,
        relation_proof_digest: id(97),
        zkpi_digest: id(98),
        issued_at: 50,
    }
}

#[test]
fn unguaranteed_receivable_is_valid_when_series_policy_allows_it() {
    let attestor = signer(101);
    let mut book = AethelBook::default();
    register_provider(
        &mut book,
        10,
        provider(1, &attestor, &[ProviderCapability::StreamAttestor], None),
    );
    register_stream(&mut book, &attestor);
    register_series(&mut book, policy(false, false, false));

    let request = issuance(&book, None, None, None);
    book.issue_receivable(request, 50).unwrap();

    assert_eq!(book.stream(&id(20)).unwrap().state.version, 2);
    assert!(book.validate().is_ok());
}

#[test]
fn assessor_guarantor_and_liquidity_provider_are_independent_capabilities() {
    let attestor = signer(101);
    let assessor = signer(102);
    let guarantor = signer(103);
    let funder = signer(104);
    let mut book = AethelBook::default();
    register_provider(
        &mut book,
        10,
        provider(1, &attestor, &[ProviderCapability::StreamAttestor], None),
    );
    register_provider(
        &mut book,
        11,
        provider(2, &assessor, &[ProviderCapability::CreditAssessor], None),
    );
    register_provider(
        &mut book,
        12,
        provider(3, &guarantor, &[ProviderCapability::Guarantor], Some(43)),
    );
    register_provider(
        &mut book,
        13,
        provider(4, &funder, &[ProviderCapability::LiquidityProvider], None),
    );
    register_stream(&mut book, &attestor);
    register_series(&mut book, policy(true, true, true));
    let stream = &book.stream(&id(20)).unwrap().state;
    let stream_root = stream.root().unwrap();

    let mut decision = CreditDecision {
        operation_id: id(51),
        decision_id: id(52),
        request_id: id(50),
        provider_id: id(2),
        series_id: id(34),
        stream_state_version: 1,
        stream_state_root: stream_root,
        model_digest: id(53),
        policy_digest: id(54),
        decision_terms_commitment: id(55),
        relation_proof_digest: id(56),
        valid_until: 500,
        nonce: id(57),
        signature: Vec::new(),
    };
    decision.signature = assessor
        .sign(&decision.statement().unwrap())
        .to_bytes()
        .to_vec();
    book.record_credit_decision(decision, 45).unwrap();

    let mut guarantee = GuaranteeCommitment {
        operation_id: id(60),
        guarantee_id: id(61),
        request_id: id(50),
        provider_id: id(3),
        series_id: id(34),
        stream_state_version: 1,
        stream_state_root: stream_root,
        credit_decision_id: Some(id(52)),
        defmi_facility_id: id(62),
        defmi_hold_id: id(63),
        coverage_commitment: id(64),
        loss_layer: LossLayer::FirstLoss,
        guarantee_terms_digest: id(65),
        claim_policy_digest: id(38),
        relation_proof_digest: id(66),
        valid_until: 500,
        nonce: id(67),
        signature: Vec::new(),
        status: GuaranteeStatus::Available,
        bound_issuance_id: None,
    };
    guarantee.signature = guarantor
        .sign(&guarantee.statement().unwrap())
        .to_bytes()
        .to_vec();
    book.record_guarantee(guarantee, 46).unwrap();

    let mut quote = FundingQuote {
        operation_id: id(70),
        quote_id: id(71),
        request_id: id(50),
        provider_id: id(4),
        series_id: id(34),
        stream_state_version: 1,
        stream_state_root: stream_root,
        credit_decision_id: Some(id(52)),
        guarantee_id: Some(id(61)),
        cash_asset_id: id(23),
        cash_reservation_id: id(72),
        advance_commitment: id(73),
        price_commitment: id(74),
        quote_terms_digest: id(75),
        policy_digest: id(76),
        relation_proof_digest: id(77),
        valid_until: 500,
        nonce: id(78),
        signature: Vec::new(),
        bound_issuance_id: None,
    };
    quote.signature = funder.sign(&quote.statement().unwrap()).to_bytes().to_vec();
    book.record_funding_quote(quote, 47).unwrap();

    book.issue_receivable(
        issuance(&book, Some(id(52)), Some(id(61)), Some(id(71))),
        50,
    )
    .unwrap();

    assert_eq!(
        book.guarantees.get(&hex::encode(id(61))).unwrap().status,
        GuaranteeStatus::Bound
    );
    assert_eq!(
        book.funding_quotes
            .get(&hex::encode(id(71)))
            .unwrap()
            .bound_issuance_id,
        Some(id(91))
    );
    assert!(book.validate().is_ok());

    let mut mismatched_snapshot = book.clone();
    mismatched_snapshot
        .issuances
        .get_mut(&hex::encode(id(91)))
        .unwrap()
        .request_id = id(99);
    assert_eq!(
        mismatched_snapshot.validate(),
        Err(AethelError::InvalidState)
    );
}

#[test]
fn credit_decision_cannot_substitute_for_required_guarantee() {
    let attestor = signer(101);
    let assessor = signer(102);
    let mut book = AethelBook::default();
    register_provider(
        &mut book,
        10,
        provider(1, &attestor, &[ProviderCapability::StreamAttestor], None),
    );
    register_provider(
        &mut book,
        11,
        provider(2, &assessor, &[ProviderCapability::CreditAssessor], None),
    );
    register_stream(&mut book, &attestor);
    register_series(&mut book, policy(true, true, false));
    let stream = &book.stream(&id(20)).unwrap().state;
    let mut decision = CreditDecision {
        operation_id: id(51),
        decision_id: id(52),
        request_id: id(50),
        provider_id: id(2),
        series_id: id(34),
        stream_state_version: 1,
        stream_state_root: stream.root().unwrap(),
        model_digest: id(53),
        policy_digest: id(54),
        decision_terms_commitment: id(55),
        relation_proof_digest: id(56),
        valid_until: 500,
        nonce: id(57),
        signature: Vec::new(),
    };
    decision.signature = assessor
        .sign(&decision.statement().unwrap())
        .to_bytes()
        .to_vec();
    book.record_credit_decision(decision, 45).unwrap();

    assert_eq!(
        book.issue_receivable(issuance(&book, Some(id(52)), None, None), 50),
        Err(AethelError::MissingRequiredArtifact)
    );
}

#[test]
fn guarantor_capability_requires_a_defmi_guarantor_identity() {
    let key = signer(103);
    assert_eq!(
        provider(3, &key, &[ProviderCapability::Guarantor], None).validate_initial(),
        Err(AethelError::MissingGuaranteeAuthority)
    );
}

#[test]
fn one_operator_can_bundle_credit_guarantee_and_liquidity_capabilities() {
    let aethel_operator = signer(105);
    let bundled = provider(
        5,
        &aethel_operator,
        &[
            ProviderCapability::CreditAssessor,
            ProviderCapability::Guarantor,
            ProviderCapability::LiquidityProvider,
        ],
        Some(45),
    );
    bundled.validate_initial().unwrap();

    let mut book = AethelBook::default();
    register_provider(&mut book, 15, bundled);
    let registered = book.provider(&id(5)).unwrap();
    assert!(registered.has(ProviderCapability::CreditAssessor, 50));
    assert!(registered.has(ProviderCapability::Guarantor, 50));
    assert!(registered.has(ProviderCapability::LiquidityProvider, 50));
}

fn kyb() -> Qualification {
    Qualification {
        namespace: "jp.kyb".into(),
        predicate_digest: id(130),
    }
}

fn confidential_policy() -> SeriesPolicy {
    let mut policy = policy(true, true, false);
    policy.requires_confidential_subject = true;
    policy.required_qualifications = vec![kyb()];
    policy
}

fn dekyx_definition(provider: u8, key: &SigningKey, epoch: u64) -> IssuerDefinition {
    IssuerDefinition {
        issuer_id: id(provider),
        key_epoch: epoch,
        public_key: key.verifying_key().to_bytes(),
        supported_subjects: BTreeSet::from([SubjectKind::LegalEntity]),
        namespace_digest: id(131),
        valid_from: 1,
        valid_until: 2_000,
        status: IssuerStatus::Active,
    }
}

fn issuer_registration(
    operation: u8,
    provider: u8,
    provider_key: &SigningKey,
    definition: IssuerDefinition,
    previous_epochs_valid_until: Option<u64>,
) -> RegisterCredentialIssuer {
    let mut request = RegisterCredentialIssuer {
        operation_id: id(operation),
        provider_id: id(provider),
        issuer: definition,
        previous_epochs_valid_until,
        signature: Vec::new(),
    };
    request.signature = provider_key
        .sign(&request.statement().unwrap())
        .to_bytes()
        .to_vec();
    request
}

fn status_publication(
    operation: u8,
    issuer: &CredentialIssuer,
    status_epoch: u64,
    revoked: Vec<[u8; 32]>,
) -> PublishCredentialStatus {
    PublishCredentialStatus {
        operation_id: id(operation),
        status_list: issuer
            .issue_status_list(status_epoch, 1, 1_900, revoked)
            .unwrap(),
    }
}

fn credential_for(
    issuer: &CredentialIssuer,
    definition: &IssuerDefinition,
    witness: &CredentialWitness,
    credential_id: u8,
    scope: u8,
) -> Credential {
    let request = CredentialRequest {
        credential_id: id(credential_id),
        issuer_id: definition.issuer_id,
        issuer_key_epoch: definition.key_epoch,
        subject_kind: SubjectKind::LegalEntity,
        subject_commitment: witness.subject_commitment(),
        scope_digest: id(scope),
        policy_digest: id(37),
        qualifications: vec![kyb()],
        status_epoch: 1,
        valid_from: 1,
        valid_until: 900,
    };
    let proof = witness.prove_issuance(&request, &mut OsRng).unwrap();
    issuer.issue(request, proof).unwrap()
}

fn present(
    book: &AethelBook,
    credential: &Credential,
    witness: &CredentialWitness,
    artifact: ConfidentialArtifact<'_>,
) -> AnonymousPresentation {
    AnonymousPresentation::create(
        credential.clone(),
        witness,
        book.presentation_context(artifact).unwrap(),
        &[kyb()],
        &mut OsRng,
    )
    .unwrap()
}

fn signed_decision(
    book: &AethelBook,
    assessor: &SigningKey,
    operation: u8,
    decision_id: u8,
    request_id: u8,
    nonce: u8,
) -> CreditDecision {
    let stream = &book.stream(&id(20)).unwrap().state;
    let mut decision = CreditDecision {
        operation_id: id(operation),
        decision_id: id(decision_id),
        request_id: id(request_id),
        provider_id: id(2),
        series_id: id(34),
        stream_state_version: stream.version,
        stream_state_root: stream.root().unwrap(),
        model_digest: id(53),
        policy_digest: id(54),
        decision_terms_commitment: id(28),
        relation_proof_digest: id(56),
        valid_until: 500,
        nonce: id(nonce),
        signature: Vec::new(),
    };
    decision.signature = assessor
        .sign(&decision.statement().unwrap())
        .to_bytes()
        .to_vec();
    decision
}

// Six small identifiers name one guarantee fixture; a struct would only
// restate the field names at every call site.
#[allow(clippy::too_many_arguments)]
fn signed_guarantee(
    book: &AethelBook,
    guarantor: &SigningKey,
    operation: u8,
    guarantee_id: u8,
    request_id: u8,
    decision_id: u8,
    hold: u8,
    nonce: u8,
) -> GuaranteeCommitment {
    let stream = &book.stream(&id(20)).unwrap().state;
    let mut guarantee = GuaranteeCommitment {
        operation_id: id(operation),
        guarantee_id: id(guarantee_id),
        request_id: id(request_id),
        provider_id: id(3),
        series_id: id(34),
        stream_state_version: stream.version,
        stream_state_root: stream.root().unwrap(),
        credit_decision_id: Some(id(decision_id)),
        defmi_facility_id: id(62),
        defmi_hold_id: id(hold),
        coverage_commitment: id(64),
        loss_layer: LossLayer::FirstLoss,
        guarantee_terms_digest: id(65),
        claim_policy_digest: id(38),
        relation_proof_digest: id(66),
        valid_until: 500,
        nonce: id(nonce),
        signature: Vec::new(),
        status: GuaranteeStatus::Available,
        bound_issuance_id: None,
    };
    guarantee.signature = guarantor
        .sign(&guarantee.statement().unwrap())
        .to_bytes()
        .to_vec();
    guarantee
}

/// Attestor 1, assessor 2, guarantor 3, credential-issuer provider 4 (key
/// `signer(104)`), one stream, one confidential series, and a registered
/// DeKYX issuer key `signer(140)` at epoch 1 with an empty status list.
fn confidential_fixture() -> (AethelBook, IssuerDefinition, CredentialIssuer) {
    let attestor = signer(101);
    let assessor = signer(102);
    let guarantor = signer(103);
    let issuer_provider = signer(104);
    let mut book = AethelBook::default();
    register_provider(
        &mut book,
        10,
        provider(1, &attestor, &[ProviderCapability::StreamAttestor], None),
    );
    register_provider(
        &mut book,
        11,
        provider(2, &assessor, &[ProviderCapability::CreditAssessor], None),
    );
    register_provider(
        &mut book,
        12,
        provider(3, &guarantor, &[ProviderCapability::Guarantor], Some(43)),
    );
    register_provider(
        &mut book,
        13,
        provider(
            4,
            &issuer_provider,
            &[ProviderCapability::CredentialIssuer],
            None,
        ),
    );
    register_stream(&mut book, &attestor);
    register_series(&mut book, confidential_policy());
    let dekyx_key = signer(140);
    let definition = dekyx_definition(4, &dekyx_key, 1);
    let issuer = CredentialIssuer::new(definition.clone(), dekyx_key).unwrap();
    book.register_credential_issuer(
        issuer_registration(140, 4, &issuer_provider, definition.clone(), None),
        41,
    )
    .unwrap();
    (book, definition, issuer)
}

#[test]
fn confidential_series_links_credit_and_guarantee_to_one_dekyx_line() {
    let (mut book, definition, issuer) = confidential_fixture();
    let assessor = signer(102);
    let guarantor = signer(103);
    let witness = CredentialWitness::random(vec![kyb()], &mut OsRng).unwrap();
    let credential = credential_for(&issuer, &definition, &witness, 150, 50);
    let decision = signed_decision(&book, &assessor, 51, 52, 50, 57);

    // A confidential series does not accept a bare provider artifact.
    assert_eq!(
        book.record_credit_decision(decision.clone(), 45),
        Err(AethelError::MissingConfidentialSubject)
    );
    // Until the issuer publishes a status list, DeKYX fails closed.
    let presentation = present(
        &book,
        &credential,
        &witness,
        ConfidentialArtifact::CreditDecision(&decision),
    );
    assert_eq!(
        book.record_confidential_credit_decision(&presentation, decision.clone(), 45),
        Err(AethelError::Credential(DeKyxError::MissingStatusList))
    );
    book.publish_credential_status(status_publication(141, &issuer, 1, vec![]), 42)
        .unwrap();

    // A credential issued by the assessor itself names a provider without the
    // credential-issuer capability and is refused before any DeKYX check.
    let assessor_dekyx = signer(141);
    let assessor_definition = dekyx_definition(2, &assessor_dekyx, 1);
    let assessor_issuer =
        CredentialIssuer::new(assessor_definition.clone(), assessor_dekyx).unwrap();
    let self_issued = credential_for(&assessor_issuer, &assessor_definition, &witness, 151, 50);
    let self_presentation = present(
        &book,
        &self_issued,
        &witness,
        ConfidentialArtifact::CreditDecision(&decision),
    );
    assert_eq!(
        book.record_confidential_credit_decision(&self_presentation, decision.clone(), 45),
        Err(AethelError::MissingProviderCapability)
    );

    let before = book.clone();
    book.record_confidential_credit_decision(&presentation, decision.clone(), 45)
        .unwrap();
    let binding = book.confidential_subject(&id(50)).unwrap().clone();
    assert_eq!(binding.issuer_provider_id, id(4));
    assert_eq!(binding.issuer_key_epoch, 1);
    assert_eq!(binding.subject_commitment, witness.subject_commitment());
    assert_eq!(binding.subject_nullifier, presentation.nullifier);
    assert_eq!(binding.policy_digest, id(37));
    assert_eq!(binding.proof_digest, presentation.digest().unwrap());

    // The guarantee needs its own presentation: the decision's transcript is
    // bound to the decision and a tampered transcript fails the proof.
    let guarantee = signed_guarantee(&book, &guarantor, 60, 61, 50, 52, 63, 67);
    assert_eq!(
        book.record_confidential_guarantee(&presentation, guarantee.clone(), 46),
        Err(AethelError::Credential(DeKyxError::RequirementMismatch))
    );
    let guarantee_presentation = present(
        &book,
        &credential,
        &witness,
        ConfidentialArtifact::Guarantee(&guarantee),
    );
    let mut tampered = guarantee_presentation.clone();
    tampered.response_subject[0] ^= 1;
    assert!(matches!(
        book.record_confidential_guarantee(&tampered, guarantee.clone(), 46),
        Err(AethelError::Credential(_))
    ));
    book.record_confidential_guarantee(&guarantee_presentation, guarantee, 46)
        .unwrap();
    assert_eq!(guarantee_presentation.nullifier, presentation.nullifier);
    assert_ne!(
        guarantee_presentation.digest().unwrap(),
        presentation.digest().unwrap()
    );
    // The line keeps the first binding; both transcripts are consumed.
    assert_eq!(
        book.confidential_subject(&id(50)).unwrap().proof_digest,
        presentation.digest().unwrap()
    );
    assert_eq!(book.consumed_presentations.len(), 2);
    assert_eq!(book.used_subject_nullifiers.len(), 1);
    book.validate().unwrap();
    assert_ne!(before.root().unwrap(), book.root().unwrap());

    // Persisted state round-trips through the validated DeKYX directory.
    let encoded = serde_json::to_string(&book).unwrap();
    let reloaded: AethelBook = serde_json::from_str(&encoded).unwrap();
    assert_eq!(reloaded, book);
    reloaded.validate().unwrap();
}

#[test]
fn revocation_and_key_rotation_govern_new_artifacts_on_a_line() {
    let (mut book, definition, issuer) = confidential_fixture();
    let assessor = signer(102);
    let guarantor = signer(103);
    let issuer_provider = signer(104);
    book.publish_credential_status(status_publication(141, &issuer, 1, vec![]), 42)
        .unwrap();
    let witness = CredentialWitness::random(vec![kyb()], &mut OsRng).unwrap();
    let credential = credential_for(&issuer, &definition, &witness, 150, 50);
    let decision = signed_decision(&book, &assessor, 51, 52, 50, 57);
    let presentation = present(
        &book,
        &credential,
        &witness,
        ConfidentialArtifact::CreditDecision(&decision),
    );
    book.record_confidential_credit_decision(&presentation, decision, 45)
        .unwrap();
    let line = book.confidential_subject(&id(50)).unwrap().clone();

    // Revocation: a newer status list naming the credential stops new artifacts.
    book.publish_credential_status(
        status_publication(142, &issuer, 2, vec![credential.digest().unwrap()]),
        46,
    )
    .unwrap();
    let guarantee = signed_guarantee(&book, &guarantor, 60, 61, 50, 52, 63, 67);
    let revoked_presentation = present(
        &book,
        &credential,
        &witness,
        ConfidentialArtifact::Guarantee(&guarantee),
    );
    assert_eq!(
        book.record_confidential_guarantee(&revoked_presentation, guarantee.clone(), 46),
        Err(AethelError::Credential(DeKyxError::RevokedCredential))
    );
    // An older or equal status epoch cannot lift the revocation, and a list
    // signed by a key that is not the registered issuer key is refused.
    assert_eq!(
        book.publish_credential_status(status_publication(143, &issuer, 2, vec![]), 46),
        Err(AethelError::Credential(DeKyxError::StaleStatusList))
    );
    let impostor =
        CredentialIssuer::new(dekyx_definition(4, &signer(143), 1), signer(143)).unwrap();
    assert_eq!(
        book.publish_credential_status(status_publication(144, &impostor, 3, vec![]), 46),
        Err(AethelError::Credential(
            DeKyxError::InvalidStatusListSignature
        ))
    );

    // Key rotation must come from the vouching provider and must say what
    // happens to the earlier epoch.
    let rotated_key = signer(145);
    let rotated = dekyx_definition(4, &rotated_key, 2);
    assert_eq!(
        book.register_credential_issuer(
            issuer_registration(146, 4, &signer(102), rotated.clone(), Some(0)),
            47,
        ),
        Err(AethelError::InvalidSignature)
    );
    assert_eq!(
        book.register_credential_issuer(
            issuer_registration(146, 4, &issuer_provider, rotated.clone(), None),
            47,
        ),
        Err(AethelError::InvalidCredentialIssuer)
    );
    book.register_credential_issuer(
        issuer_registration(146, 4, &issuer_provider, rotated.clone(), Some(0)),
        47,
    )
    .unwrap();
    assert_eq!(
        book.credential_issuers.issuer(&id(4), 1).unwrap().status,
        IssuerStatus::Revoked
    );
    let rotated_issuer = CredentialIssuer::new(rotated.clone(), rotated_key).unwrap();
    book.publish_credential_status(status_publication(147, &rotated_issuer, 1, vec![]), 47)
        .unwrap();

    // The re-issued credential under the new key continues the same line.
    let reissued = credential_for(&rotated_issuer, &rotated, &witness, 152, 50);
    let reissued_presentation = present(
        &book,
        &reissued,
        &witness,
        ConfidentialArtifact::Guarantee(&guarantee),
    );
    book.record_confidential_guarantee(&reissued_presentation, guarantee, 48)
        .unwrap();
    let stored = book.confidential_subject(&id(50)).unwrap();
    assert!(stored.same_subject_line(&line));
    assert_eq!(stored.issuer_key_epoch, 1);
    assert_eq!(reissued_presentation.nullifier, line.subject_nullifier);
    // A presentation under the retired epoch is no longer accepted at all.
    let second_decision = signed_decision(&book, &assessor, 70, 71, 50, 72);
    let retired_presentation = present(
        &book,
        &credential,
        &witness,
        ConfidentialArtifact::CreditDecision(&second_decision),
    );
    assert_eq!(
        book.record_confidential_credit_decision(&retired_presentation, second_decision, 48),
        Err(AethelError::Credential(DeKyxError::IssuerNotAuthorized))
    );
    book.validate().unwrap();
}

#[test]
fn one_subject_in_two_request_scopes_yields_unlinked_lines() {
    let (mut book, definition, issuer) = confidential_fixture();
    let assessor = signer(102);
    book.publish_credential_status(status_publication(141, &issuer, 1, vec![]), 42)
        .unwrap();
    let witness = CredentialWitness::random(vec![kyb()], &mut OsRng).unwrap();
    let other_scope_witness = witness.rerandomize(&mut OsRng);
    let first = credential_for(&issuer, &definition, &witness, 150, 50);
    let second = credential_for(&issuer, &definition, &other_scope_witness, 151, 122);

    let first_decision = signed_decision(&book, &assessor, 51, 52, 50, 57);
    let first_presentation = present(
        &book,
        &first,
        &witness,
        ConfidentialArtifact::CreditDecision(&first_decision),
    );
    book.record_confidential_credit_decision(&first_presentation, first_decision, 45)
        .unwrap();
    let second_decision = signed_decision(&book, &assessor, 120, 121, 122, 123);
    // The first credential cannot be presented for the second line at all.
    assert_eq!(
        AnonymousPresentation::create(
            first.clone(),
            &witness,
            book.presentation_context(ConfidentialArtifact::CreditDecision(&second_decision))
                .unwrap(),
            &[kyb()],
            &mut OsRng,
        )
        .map(|_| ()),
        Err(DeKyxError::MismatchedWitnessOrContext)
    );
    let second_presentation = present(
        &book,
        &second,
        &other_scope_witness,
        ConfidentialArtifact::CreditDecision(&second_decision),
    );
    book.record_confidential_credit_decision(&second_presentation, second_decision, 46)
        .unwrap();

    let line_a = book.confidential_subject(&id(50)).unwrap();
    let line_b = book.confidential_subject(&id(122)).unwrap();
    assert_ne!(line_a.subject_commitment, line_b.subject_commitment);
    assert_ne!(line_a.subject_nullifier, line_b.subject_nullifier);
    assert_ne!(line_a.subject_line_id, line_b.subject_line_id);
    assert!(!line_a.same_subject_line(line_b));
    assert_eq!(book.used_subject_nullifiers.len(), 2);
    book.validate().unwrap();
}

fn provider_rotation(
    provider: u8,
    next: &SigningKey,
    signer_of_request: &SigningKey,
    operation: u8,
    expected_sequence: u64,
    rotated_at: u64,
) -> RotateProviderKey {
    let mut rotation = RotateProviderKey {
        operation_id: id(operation),
        provider_id: id(provider),
        next_public_key: next.verifying_key().to_bytes(),
        expected_sequence,
        rotated_at,
        signature: Vec::new(),
    };
    rotation.signature = signer_of_request
        .sign(&rotation.statement().unwrap())
        .to_bytes()
        .to_vec();
    rotation
}

fn provider_status(
    provider: u8,
    status: ProviderStatus,
    operation: u8,
    expected_sequence: u64,
    effective_at: u64,
) -> SetProviderStatus {
    SetProviderStatus {
        operation_id: id(operation),
        provider_id: id(provider),
        status,
        expected_sequence,
        effective_at,
    }
}

#[test]
fn provider_key_rotation_retires_the_old_key_but_keeps_what_it_recorded() {
    let attestor = signer(101);
    let assessor = signer(102);
    let mut book = AethelBook::default();
    register_provider(
        &mut book,
        10,
        provider(1, &attestor, &[ProviderCapability::StreamAttestor], None),
    );
    register_provider(
        &mut book,
        11,
        provider(2, &assessor, &[ProviderCapability::CreditAssessor], None),
    );
    register_stream(&mut book, &attestor);
    register_series(&mut book, policy(true, false, false));
    let first = signed_decision(&book, &assessor, 51, 52, 50, 57);
    book.record_credit_decision(first.clone(), 45).unwrap();

    // Possession of the next key is what the request proves; the old key
    // cannot sign a rotation, and the sequence names the exact prior state.
    let next = signer(112);
    assert_eq!(
        book.rotate_provider_key(provider_rotation(2, &next, &assessor, 70, 0, 46), 46),
        Err(AethelError::InvalidSignature)
    );
    assert_eq!(
        book.rotate_provider_key(provider_rotation(2, &next, &next, 70, 1, 46), 46),
        Err(AethelError::StaleSequence)
    );
    book.rotate_provider_key(provider_rotation(2, &next, &next, 70, 0, 46), 46)
        .unwrap();
    let rotated = book.provider(&id(2)).unwrap().clone();
    assert_eq!(rotated.sequence, 1);
    assert_eq!(rotated.public_key, next.verifying_key().to_bytes());
    assert_eq!(rotated.retired_keys.len(), 1);
    assert_eq!(rotated.retired_keys[0].retired_at, 46);
    assert_eq!(
        rotated.registration_key(),
        assessor.verifying_key().to_bytes()
    );

    // The retired key signs nothing new; the next key does; the decision the
    // retired key signed while it was live is still part of a valid book.
    assert_eq!(
        book.record_credit_decision(signed_decision(&book, &assessor, 71, 72, 50, 73), 47),
        Err(AethelError::InvalidSignature)
    );
    book.record_credit_decision(signed_decision(&book, &next, 71, 72, 50, 73), 47)
        .unwrap();
    book.validate().unwrap();
    assert_eq!(book.credit_decisions.len(), 2);
    // A key that was ever the provider's cannot come back.
    assert_eq!(
        book.rotate_provider_key(provider_rotation(2, &assessor, &assessor, 74, 1, 48), 48),
        Err(AethelError::InvalidProviderKey)
    );

    // Suspension stops new artifacts, reinstatement resumes them, revocation
    // is terminal and blocks rotation too. Nothing recorded is removed.
    book.set_provider_status(provider_status(2, ProviderStatus::Suspended, 75, 1, 49), 49)
        .unwrap();
    let while_suspended = signed_decision(&book, &next, 76, 77, 50, 78);
    assert_eq!(
        book.record_credit_decision(while_suspended.clone(), 49),
        Err(AethelError::MissingProviderCapability)
    );
    assert_eq!(
        book.set_provider_status(provider_status(2, ProviderStatus::Active, 79, 1, 50), 50),
        Err(AethelError::StaleSequence)
    );
    book.set_provider_status(provider_status(2, ProviderStatus::Active, 79, 2, 50), 50)
        .unwrap();
    book.record_credit_decision(while_suspended, 50).unwrap();
    book.set_provider_status(provider_status(2, ProviderStatus::Revoked, 80, 3, 51), 51)
        .unwrap();
    assert_eq!(
        book.set_provider_status(provider_status(2, ProviderStatus::Active, 81, 4, 52), 52),
        Err(AethelError::ProviderRevoked)
    );
    assert_eq!(
        book.rotate_provider_key(
            provider_rotation(2, &signer(113), &signer(113), 82, 4, 52),
            52
        ),
        Err(AethelError::ProviderRevoked)
    );
    assert_eq!(book.provider(&id(2)).unwrap().sequence, 4);
    assert_eq!(book.credit_decisions.len(), 3);
    book.validate().unwrap();
    let reloaded: AethelBook =
        serde_json::from_str(&serde_json::to_string(&book).unwrap()).unwrap();
    assert_eq!(reloaded, book);
    reloaded.validate().unwrap();
}

#[test]
fn guarantor_can_release_only_its_own_unbound_guarantee() {
    let attestor = signer(101);
    let assessor = signer(102);
    let guarantor = signer(103);
    let mut book = AethelBook::default();
    register_provider(
        &mut book,
        10,
        provider(1, &attestor, &[ProviderCapability::StreamAttestor], None),
    );
    register_provider(
        &mut book,
        11,
        provider(2, &assessor, &[ProviderCapability::CreditAssessor], None),
    );
    register_provider(
        &mut book,
        12,
        provider(3, &guarantor, &[ProviderCapability::Guarantor], Some(43)),
    );
    register_stream(&mut book, &attestor);
    register_series(&mut book, policy(true, true, false));
    book.record_credit_decision(signed_decision(&book, &assessor, 51, 52, 50, 57), 45)
        .unwrap();
    book.record_guarantee(
        signed_guarantee(&book, &guarantor, 60, 61, 50, 52, 63, 67),
        46,
    )
    .unwrap();

    let release_by = |signer: &SigningKey, provider: u8, guarantee: u8, operation: u8, at: u64| {
        let mut release = GuaranteeRelease {
            operation_id: id(operation),
            guarantee_id: id(guarantee),
            provider_id: id(provider),
            defmi_settlement_digest: id(83),
            relation_proof_digest: id(84),
            released_at: at,
            signature: Vec::new(),
        };
        release.signature = signer
            .sign(&release.statement().unwrap())
            .to_bytes()
            .to_vec();
        release
    };
    // Only a guarantor provider may release, and only its own guarantee.
    assert_eq!(
        book.release_guarantee(release_by(&assessor, 2, 61, 85, 47), 47),
        Err(AethelError::MissingProviderCapability)
    );
    book.release_guarantee(release_by(&guarantor, 3, 61, 85, 47), 47)
        .unwrap();
    assert_eq!(
        book.guarantees.get(&hex::encode(id(61))).unwrap().status,
        GuaranteeStatus::Released
    );
    // A released guarantee backs nothing and cannot be released twice.
    assert_eq!(
        book.issue_receivable(issuance(&book, Some(id(52)), Some(id(61)), None), 50),
        Err(AethelError::MismatchedArtifact)
    );
    assert_eq!(
        book.release_guarantee(release_by(&guarantor, 3, 61, 86, 51), 51),
        Err(AethelError::GuaranteeUnavailable)
    );
    book.validate().unwrap();

    // A bound guarantee is not releasable: it covers a live note.
    book.record_guarantee(
        signed_guarantee(&book, &guarantor, 87, 88, 50, 52, 89, 90),
        52,
    )
    .unwrap();
    book.issue_receivable(issuance(&book, Some(id(52)), Some(id(88)), None), 50)
        .unwrap();
    assert_eq!(
        book.release_guarantee(release_by(&guarantor, 3, 88, 91, 53), 53),
        Err(AethelError::GuaranteeUnavailable)
    );
    book.validate().unwrap();
}
