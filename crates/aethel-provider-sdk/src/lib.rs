//! The open provider contract of Aethel.
//!
//! Aethel's premise is that a signed payment stream is itself the receivable,
//! and that independent institutions plug into it: a stream attestor vouches
//! for the stream's source data, a credit assessor underwrites it, a guarantor
//! commits risk capital, a liquidity provider quotes an advance, a servicer
//! observes payment and default, and a credential issuer vouches for a DeKYX
//! issuer key. This crate is what such a provider builds against. It carries
//!
//! - the provider record: capabilities, artifact key with rotation history,
//!   validity window, status, and the control operations that change them;
//! - every provider-signed artifact type, each with its statement digest;
//! - the [`SignedArtifact`] and [`ProviderRegistry`] contract that a verifier
//!   uses to accept an artifact only from a provider whose capability for it
//!   is active, under that provider's current key.
//!
//! It deliberately does not contain the Aethel state machine, any balance,
//! any credential logic (DeKYX owns that), or any guarantee capacity (DeCCP
//! owns that). A provider integrates with this crate alone; the protocol
//! crate re-exports these types so existing callers are unaffected.

#![forbid(unsafe_code)]

mod artifacts;
mod contract;
mod credential;
mod error;
mod provider;
mod stream;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

pub use artifacts::{
    CreditDecision, DefaultAttestation, FundingQuote, GuaranteeCommitment, GuaranteeRelease,
    GuaranteeStatus, LossLayer,
};
pub use contract::{sign_artifact, ProviderRegistry, SignedArtifact};
pub use credential::{PublishCredentialStatus, RegisterCredentialIssuer};
pub use error::ProviderError;
pub use provider::{
    sign_provider_statement, ProviderCapability, ProviderDefinition, ProviderStatus,
    RegisterProvider, RetiredProviderKey, RotateProviderKey, SetProviderStatus,
    PROVIDER_SIGNATURE_SUITE,
};
pub use stream::{RegisterStream, StreamState, StreamStatus, StreamTransition};

/// DeKYX is re-exported so a credential-issuer provider builds its issuer
/// definition with exactly the version this contract verifies against.
pub use dekyx_core;

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use ed25519_dalek::SigningKey;

    use super::*;

    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn sign_artifact<A: SignedArtifact>(
        artifact: &mut A,
        key: &SigningKey,
    ) -> Result<aethel_types::Commitment, ProviderError> {
        super::sign_artifact(
            artifact,
            &test_support::signer(key),
            &test_support::key_record(key, id(2), 1),
        )
    }

    fn definition(key: &SigningKey, capabilities: &[ProviderCapability]) -> ProviderDefinition {
        ProviderDefinition {
            provider_id: id(1),
            participant_id: id(2),
            capabilities: capabilities.iter().copied().collect::<BTreeSet<_>>(),
            public_key: key.verifying_key().to_bytes(),
            artifact_key: test_support::key_record(key, id(2), 1),
            policy_registry_digest: id(3),
            defmi_guarantor_id: None,
            valid_from: 1,
            valid_until: 1_000,
            sequence: 0,
            status: ProviderStatus::Active,
            retired_keys: Vec::new(),
        }
    }

    fn decision() -> CreditDecision {
        CreditDecision {
            operation_id: id(10),
            decision_id: id(11),
            request_id: id(12),
            provider_id: id(1),
            series_id: id(13),
            stream_state_version: 1,
            stream_state_root: id(14),
            model_digest: id(15),
            policy_digest: id(16),
            decision_terms_commitment: id(17),
            relation_proof_digest: id(18),
            valid_until: 500,
            nonce: id(19),
            signature: Vec::new(),
        }
    }

    fn registry(provider: ProviderDefinition) -> BTreeMap<String, ProviderDefinition> {
        BTreeMap::from([(aethel_types::id_key(&provider.provider_id), provider)])
    }

    #[test]
    fn an_artifact_is_accepted_only_under_the_capability_it_needs() {
        let key = SigningKey::from_bytes(&id(101));
        let mut decision = decision();
        let statement = sign_artifact(&mut decision, &key).unwrap();
        assert_eq!(decision.statement().unwrap(), statement);

        let assessor = registry(definition(&key, &[ProviderCapability::CreditAssessor]));
        assert_eq!(assessor.verify_artifact(&decision, 100), Ok(statement));

        let guarantor_only = registry(definition(&key, &[ProviderCapability::LiquidityProvider]));
        assert_eq!(
            guarantor_only.verify_artifact(&decision, 100),
            Err(ProviderError::MissingProviderCapability)
        );
        assert_eq!(
            BTreeMap::new().verify_artifact(&decision, 100),
            Err(ProviderError::UnknownProvider)
        );
        assert_eq!(
            assessor.verify_artifact(&decision, 1_001),
            Err(ProviderError::MissingProviderCapability)
        );
    }

    #[test]
    fn a_malformed_artifact_is_never_signed() {
        let key = SigningKey::from_bytes(&id(101));
        let mut decision = decision();
        decision.nonce = aethel_types::ZERO;
        assert_eq!(
            sign_artifact(&mut decision, &key),
            Err(ProviderError::InvalidCreditDecision)
        );
        assert!(decision.signature.is_empty());
    }

    #[test]
    fn a_suspended_provider_signs_nothing_new_and_its_past_stays_verifiable() {
        let key = SigningKey::from_bytes(&id(101));
        let mut decision = decision();
        let statement = sign_artifact(&mut decision, &key).unwrap();
        let mut provider = definition(&key, &[ProviderCapability::CreditAssessor]);
        provider.status = ProviderStatus::Suspended;
        provider.sequence = 1;
        assert_eq!(
            registry(provider.clone()).verify_artifact(&decision, 100),
            Err(ProviderError::MissingProviderCapability)
        );
        assert_eq!(
            provider.verify_recorded_signature(&statement, &decision.signature),
            Ok(())
        );
    }

    #[test]
    fn rotation_retires_the_old_key_for_new_artifacts_only() {
        let old = SigningKey::from_bytes(&id(101));
        let next = SigningKey::from_bytes(&id(102));
        let mut decision = decision();
        let statement = sign_artifact(&mut decision, &old).unwrap();

        let mut rotation = RotateProviderKey {
            operation_id: id(20),
            provider_id: id(1),
            next_public_key: next.verifying_key().to_bytes(),
            next_artifact_key: test_support::key_record(&next, id(2), 2),
            expected_sequence: 0,
            rotated_at: 50,
            signature: Vec::new(),
        };
        // Signed by the wrong key: possession of the next key is not shown.
        rotation.signature = sign_provider_statement(
            &test_support::signer(&old),
            &test_support::key_record(&old, id(2), 2),
            &rotation.provider_id,
            &rotation.statement().unwrap(),
        )
        .unwrap();
        assert_eq!(
            rotation.verify_possession(),
            Err(ProviderError::InvalidSignature)
        );
        // Correct key under the artifact purpose cannot authorize rotation.
        rotation.signature = sign_provider_statement(
            &test_support::signer(&next),
            &rotation.next_artifact_key,
            &rotation.provider_id,
            &rotation.statement().unwrap(),
        )
        .unwrap();
        assert_eq!(
            rotation.verify_possession(),
            Err(ProviderError::InvalidSignature)
        );
        rotation
            .sign_possession(&test_support::signer(&next))
            .unwrap();
        assert!(rotation.verify_possession().is_ok());

        let mut provider = definition(&old, &[ProviderCapability::CreditAssessor]);
        provider.retired_keys.push(RetiredProviderKey {
            public_key: provider.public_key,
            artifact_key: provider.artifact_key.clone(),
            retired_at: 50,
        });
        provider.public_key = rotation.next_public_key;
        provider.artifact_key = rotation.next_artifact_key;
        provider.sequence = 1;
        provider.validate().unwrap();
        assert_eq!(
            provider.verify_new_signature(&statement, &decision.signature, 100),
            Err(ProviderError::InvalidSignature)
        );
        assert_eq!(
            provider.verify_recorded_signature(&statement, &decision.signature),
            Ok(())
        );
        assert_eq!(provider.registration_key(), old.verifying_key().to_bytes());
    }

    #[test]
    fn guarantor_capability_needs_a_defmi_authority_and_nothing_else_may_carry_one() {
        let key = SigningKey::from_bytes(&id(101));
        let guarantor = definition(&key, &[ProviderCapability::Guarantor]);
        assert_eq!(
            guarantor.validate_initial(),
            Err(ProviderError::MissingGuaranteeAuthority)
        );
        let mut assessor = definition(&key, &[ProviderCapability::CreditAssessor]);
        assessor.defmi_guarantor_id = Some(id(9));
        assert_eq!(
            assessor.validate_initial(),
            Err(ProviderError::InvalidProvider)
        );
    }

    #[test]
    fn wire_forms_round_trip_through_serde() {
        let key = SigningKey::from_bytes(&id(101));
        let mut decision = decision();
        sign_artifact(&mut decision, &key).unwrap();
        let encoded = serde_json::to_string(&decision).unwrap();
        let decoded: CreditDecision = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, decision);
        let provider = definition(&key, &[ProviderCapability::Servicer]);
        let encoded = serde_json::to_string(&provider).unwrap();
        assert_eq!(
            serde_json::from_str::<ProviderDefinition>(&encoded).unwrap(),
            provider
        );
    }
    #[test]
    fn hybrid_components_metadata_and_clock_are_mandatory() {
        use zkfmi_crypto::{
            key::KeyId,
            suite::{Suite, SuiteId},
        };
        let key = SigningKey::from_bytes(&id(101));
        let provider = definition(&key, &[ProviderCapability::CreditAssessor]);
        let mut artifact = decision();
        let statement = sign_artifact(&mut artifact, &key).unwrap();
        assert_eq!(
            provider.verify_new_signature(&statement, &artifact.signature, 100),
            Ok(())
        );
        for position in [0, 64, artifact.signature.len() - 1] {
            let mut corrupted = artifact.clone();
            corrupted.signature[position] ^= 1;
            assert_eq!(
                registry(provider.clone()).verify_artifact(&corrupted, 100),
                Err(ProviderError::InvalidSignature)
            );
        }
        for length in [0, 64, artifact.signature.len() - 1] {
            let mut truncated = artifact.clone();
            truncated.signature.truncate(length);
            assert_eq!(
                registry(provider.clone()).verify_artifact(&truncated, 100),
                Err(ProviderError::InvalidSignature)
            );
        }
        let mut extended = artifact.clone();
        extended.signature.push(0);
        assert_eq!(
            registry(provider.clone()).verify_artifact(&extended, 100),
            Err(ProviderError::InvalidSignature)
        );
        let mut changed = artifact.clone();
        changed.model_digest = id(99);
        assert_eq!(
            registry(provider.clone()).verify_artifact(&changed, 100),
            Err(ProviderError::InvalidSignature)
        );
        let mut changed_key = provider.clone();
        changed_key.artifact_key.key_id = KeyId::new("substituted-key").unwrap();
        assert_eq!(
            registry(changed_key).verify_artifact(&artifact, 100),
            Err(ProviderError::InvalidSignature)
        );
        let mut revoked = provider.clone();
        revoked.artifact_key.revoked_at = Some(100);
        assert_eq!(
            registry(revoked.clone()).verify_artifact(&artifact, 100),
            Err(ProviderError::InvalidProviderKey)
        );
        assert_eq!(
            revoked.verify_recorded_signature(&statement, &artifact.signature),
            Ok(())
        );
        let mut expired = provider.clone();
        expired.artifact_key.not_after = 100;
        assert_eq!(
            registry(expired).verify_artifact(&artifact, 100),
            Err(ProviderError::InvalidProviderKey)
        );
        let mut future = provider.clone();
        future.artifact_key.not_before = 101;
        assert_eq!(
            registry(future).verify_artifact(&artifact, 100),
            Err(ProviderError::InvalidProviderKey)
        );
        let mut classical = provider.clone();
        classical.artifact_key.suite = Suite::new(SuiteId::Ed25519);
        classical.artifact_key.public_key.truncate(32);
        assert_eq!(
            classical.validate_initial(),
            Err(ProviderError::InvalidProviderKey)
        );
        let mut wrong_purpose = provider.clone();
        wrong_purpose.artifact_key.purpose = zkfmi_crypto::key::KeyPurpose::Quote;
        assert_eq!(
            wrong_purpose.validate_initial(),
            Err(ProviderError::InvalidProviderKey)
        );
        let mut omitted = serde_json::to_value(&provider).unwrap();
        omitted.as_object_mut().unwrap().remove("artifactKey");
        assert!(serde_json::from_value::<ProviderDefinition>(omitted).is_err());
    }
}
