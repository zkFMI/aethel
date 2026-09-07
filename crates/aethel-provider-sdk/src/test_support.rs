//! Public deterministic fixtures only. Never enroll these keys in production.
//! Seeds are explicit test inputs, never derived from a public classical key.
use aethel_types::{id_key, Identifier, MAX_UNIX_TIME};
use ed25519_dalek::SigningKey;
use zkfmi_crypto::{
    backend::{Ed25519Signer, MlDsa65Signer},
    hybrid::signature::HybridSigner,
    key::{KeyId, KeyPurpose, KeyRecord, ParticipantId},
    traits::Signer,
};

pub fn signer(classical: &SigningKey) -> HybridSigner {
    // Separate publicly known fixture seed labels. This is not production KDF.
    let pq_seed = classical.to_bytes().map(|byte| byte.wrapping_add(73));
    HybridSigner::new(
        Ed25519Signer::from_seed(&classical.to_bytes()),
        MlDsa65Signer::from_seed(&pq_seed),
    )
}

pub fn key_record(
    classical: &SigningKey,
    participant_id: Identifier,
    generation: u32,
) -> KeyRecord {
    let signer = signer(classical);
    KeyRecord {
        participant_id: ParticipantId::new(id_key(&participant_id)).unwrap(),
        key_id: KeyId::new(format!(
            "aethel-provider-test-{}-{generation}",
            id_key(&classical.verifying_key().to_bytes())
        ))
        .unwrap(),
        suite: crate::PROVIDER_SIGNATURE_SUITE,
        key_version: generation,
        purpose: KeyPurpose::Attestation,
        public_key: signer.public_key(),
        not_before: 1,
        not_after: MAX_UNIX_TIME,
        revoked_at: None,
        rotation_proof: None,
        dekyx_binding: None,
    }
}
