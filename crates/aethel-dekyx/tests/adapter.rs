use std::collections::BTreeSet;

use aethel_dekyx::{AethelDeKyxAdapter, AethelEligibilityRequest};
use dekyx_core::{
    AnonymousPresentation, Credential, CredentialIssuer, CredentialRequest, CredentialWitness,
    DeKyxError, IssuerDefinition, IssuerDirectory, IssuerStatus, Qualification, SubjectKind,
};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

fn id(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn definition(key: &SigningKey, issuer: u8, epoch: u64, namespace: u8) -> IssuerDefinition {
    IssuerDefinition {
        issuer_id: id(issuer),
        key_epoch: epoch,
        public_key: key.verifying_key().to_bytes(),
        supported_subjects: BTreeSet::from([SubjectKind::LegalEntity]),
        namespace_digest: id(namespace),
        valid_from: 1,
        valid_until: 1_000,
        status: IssuerStatus::Active,
    }
}

fn kyb() -> Qualification {
    Qualification {
        namespace: "jp.kyb".into(),
        predicate_digest: id(3),
    }
}

fn issue(
    issuer: &CredentialIssuer,
    definition: &IssuerDefinition,
    witness: &CredentialWitness,
    credential_id: u8,
    scope: u8,
    policy: u8,
) -> Credential {
    let request = CredentialRequest {
        credential_id: id(credential_id),
        issuer_id: definition.issuer_id,
        issuer_key_epoch: definition.key_epoch,
        subject_kind: SubjectKind::LegalEntity,
        subject_commitment: witness.subject_commitment(),
        scope_digest: id(scope),
        policy_digest: id(policy),
        qualifications: vec![kyb()],
        status_epoch: 1,
        valid_from: 1,
        valid_until: 900,
    };
    let proof = witness.prove_issuance(&request, &mut OsRng).unwrap();
    issuer.issue(request, proof).unwrap()
}

fn request(
    definition: &IssuerDefinition,
    scope: u8,
    policy: u8,
    action: u8,
    artifact: u8,
    nonce: u8,
) -> AethelEligibilityRequest {
    AethelEligibilityRequest {
        request_id: id(scope),
        issuer_provider_id: definition.issuer_id,
        issuer_key_epoch: definition.key_epoch,
        issuer_namespace_digest: definition.namespace_digest,
        subject_kind: SubjectKind::LegalEntity,
        policy_digest: id(policy),
        required_qualifications: vec![kyb()],
        audience_digest: id(7),
        action_digest: id(action),
        artifact_digest: id(artifact),
        challenge_nonce: id(nonce),
        valid_until: 850,
    }
}

fn present(
    credential: &Credential,
    witness: &CredentialWitness,
    request: &AethelEligibilityRequest,
) -> AnonymousPresentation {
    AnonymousPresentation::create(
        credential.clone(),
        witness,
        request.context(),
        &[kyb()],
        &mut OsRng,
    )
    .unwrap()
}

#[test]
fn fresh_credit_and_guarantee_proofs_keep_one_aethel_subject_line_across_key_rotation() {
    let first_key = SigningKey::generate(&mut OsRng);
    let first = definition(&first_key, 1, 7, 2);
    let first_issuer = CredentialIssuer::new(first.clone(), first_key).unwrap();
    let witness = CredentialWitness::random(vec![kyb()], &mut OsRng).unwrap();
    let credential = issue(&first_issuer, &first, &witness, 4, 5, 6);
    let mut directory = IssuerDirectory::default();
    directory.register_issuer(first.clone()).unwrap();
    directory
        .publish_status_list(first_issuer.issue_status_list(1, 1, 950, vec![]).unwrap())
        .unwrap();

    let credit_request = request(&first, 5, 6, 8, 9, 10);
    let credit_proof = present(&credential, &witness, &credit_request);
    let adapter = AethelDeKyxAdapter {
        directory: &directory,
    };
    let credit_binding = adapter.verify(&credit_request, &credit_proof, 200).unwrap();
    // The presentation is bound to the artifact: another artifact digest fails.
    let other_artifact = AethelEligibilityRequest {
        artifact_digest: id(11),
        ..credit_request.clone()
    };
    assert_eq!(
        adapter.verify(&other_artifact, &credit_proof, 200),
        Err(DeKyxError::RequirementMismatch)
    );

    // The issuer rotates its key; the guarantee uses a re-issued credential.
    let second_key = SigningKey::generate(&mut OsRng);
    let second = definition(&second_key, 1, 8, 2);
    let second_issuer = CredentialIssuer::new(second.clone(), second_key).unwrap();
    directory.rotate_key(second.clone(), 300).unwrap();
    directory
        .publish_status_list(second_issuer.issue_status_list(1, 1, 950, vec![]).unwrap())
        .unwrap();
    let reissued = issue(&second_issuer, &second, &witness, 12, 5, 6);
    let guarantee_request = request(&second, 5, 6, 13, 14, 15);
    let guarantee_proof = present(&reissued, &witness, &guarantee_request);
    let adapter = AethelDeKyxAdapter {
        directory: &directory,
    };
    let guarantee_binding = adapter
        .verify(&guarantee_request, &guarantee_proof, 400)
        .unwrap();

    assert!(credit_binding.same_subject_line(&guarantee_binding));
    assert_ne!(
        credit_binding.issuer_key_epoch,
        guarantee_binding.issuer_key_epoch
    );
    assert_ne!(credit_binding.proof_digest, guarantee_binding.proof_digest);
    // The retired epoch no longer verifies after its grace window.
    assert_eq!(
        adapter.verify(&credit_request, &credit_proof, 400),
        Err(DeKyxError::IssuerNotAuthorized)
    );
}

#[test]
fn revoked_wrong_context_or_foreign_issuer_evidence_is_rejected() {
    let key = SigningKey::generate(&mut OsRng);
    let trusted = definition(&key, 20, 1, 21);
    let issuer = CredentialIssuer::new(trusted.clone(), key).unwrap();
    let witness = CredentialWitness::random(vec![kyb()], &mut OsRng).unwrap();
    let credential = issue(&issuer, &trusted, &witness, 23, 24, 25);
    let request = request(&trusted, 24, 25, 27, 28, 29);
    let proof = present(&credential, &witness, &request);

    let mut directory = IssuerDirectory::default();
    directory.register_issuer(trusted.clone()).unwrap();
    // No status list yet: fail closed.
    assert_eq!(
        AethelDeKyxAdapter {
            directory: &directory
        }
        .verify(&request, &proof, 200),
        Err(DeKyxError::MissingStatusList)
    );
    directory
        .publish_status_list(
            issuer
                .issue_status_list(3, 1, 950, vec![credential.digest().unwrap()])
                .unwrap(),
        )
        .unwrap();
    assert_eq!(
        AethelDeKyxAdapter {
            directory: &directory
        }
        .verify(&request, &proof, 200),
        Err(DeKyxError::RevokedCredential)
    );
    // An older list cannot lift the revocation.
    assert_eq!(
        directory.publish_status_list(issuer.issue_status_list(2, 1, 950, vec![]).unwrap()),
        Err(DeKyxError::StaleStatusList)
    );

    let mut live = IssuerDirectory::default();
    live.register_issuer(trusted.clone()).unwrap();
    live.publish_status_list(issuer.issue_status_list(3, 1, 950, vec![]).unwrap())
        .unwrap();
    let adapter = AethelDeKyxAdapter { directory: &live };
    adapter.verify(&request, &proof, 200).unwrap();
    let wrong_action = AethelEligibilityRequest {
        action_digest: id(30),
        ..request.clone()
    };
    assert_eq!(
        adapter.verify(&wrong_action, &proof, 200),
        Err(DeKyxError::RequirementMismatch)
    );
    let wrong_namespace = AethelEligibilityRequest {
        issuer_namespace_digest: id(31),
        ..request.clone()
    };
    assert_eq!(
        adapter.verify(&wrong_namespace, &proof, 200),
        Err(DeKyxError::IssuerNotAuthorized)
    );

    // A credential from an issuer that is registered but not the one the
    // request names cannot satisfy the request.
    let foreign_key = SigningKey::generate(&mut OsRng);
    let foreign = definition(&foreign_key, 40, 1, 21);
    let foreign_issuer = CredentialIssuer::new(foreign.clone(), foreign_key).unwrap();
    live.register_issuer(foreign.clone()).unwrap();
    live.publish_status_list(foreign_issuer.issue_status_list(1, 1, 950, vec![]).unwrap())
        .unwrap();
    let foreign_credential = issue(&foreign_issuer, &foreign, &witness, 41, 24, 25);
    let foreign_proof = present(&foreign_credential, &witness, &request);
    assert_eq!(
        AethelDeKyxAdapter { directory: &live }.verify(&request, &foreign_proof, 200),
        Err(DeKyxError::RequirementMismatch)
    );
}
