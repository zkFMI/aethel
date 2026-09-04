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

pub use artifacts::{
    CreditDecision, DefaultAttestation, FundingQuote, GuaranteeCommitment, GuaranteeRelease,
    GuaranteeStatus, LossLayer,
};
pub use contract::{sign_artifact, ProviderRegistry, SignedArtifact};
pub use credential::{PublishCredentialStatus, RegisterCredentialIssuer};
pub use error::ProviderError;
pub use provider::{
    ProviderCapability, ProviderDefinition, ProviderStatus, RegisterProvider, RetiredProviderKey,
    RotateProviderKey, SetProviderStatus,
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

    fn definition(key: &SigningKey, capabilities: &[ProviderCapability]) -> ProviderDefinition {
        ProviderDefinition {
            provider_id: id(1),
            participant_id: id(2),
            capabilities: capabilities.iter().copied().collect::<BTreeSet<_>>(),
            public_key: key.verifying_key().to_bytes(),
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
            expected_sequence: 0,
            rotated_at: 50,
            signature: Vec::new(),
        };
        // Signed by the wrong key: possession of the next key is not shown.
        rotation.signature = ed25519_dalek::Signer::sign(&old, &rotation.statement().unwrap())
            .to_bytes()
            .to_vec();
        assert_eq!(
            rotation.verify_possession(),
            Err(ProviderError::InvalidSignature)
        );
        rotation.signature = ed25519_dalek::Signer::sign(&next, &rotation.statement().unwrap())
            .to_bytes()
            .to_vec();
        assert!(rotation.verify_possession().is_ok());

        let mut provider = definition(&old, &[ProviderCapability::CreditAssessor]);
        provider.retired_keys.push(RetiredProviderKey {
            public_key: provider.public_key,
            retired_at: 50,
        });
        provider.public_key = rotation.next_public_key;
        provider.sequence = 1;
        provider.validate().unwrap();
        assert_eq!(
            provider.verify_new_signature(&statement, &decision.signature),
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
}
