//! The plug-in contract an external provider implements against.
//!
//! A provider produces one of the artifact types, fills every field but the
//! signature, and signs the statement digest with its current artifact key.
//! A verifier (the Aethel protocol book, a servicing book, or any host) looks
//! the provider up in a [`ProviderRegistry`], checks that the capability the
//! artifact needs is active at that instant, and verifies the signature. No
//! artifact is accepted from a provider that lacks the capability it claims,
//! whatever else the provider is registered for.

use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey};

use aethel_types::{id_key, Commitment, Identifier};

use crate::{
    CreditDecision, DefaultAttestation, FundingQuote, GuaranteeCommitment, GuaranteeRelease,
    ProviderCapability, ProviderDefinition, ProviderError, RegisterCredentialIssuer,
    RegisterStream, StreamTransition,
};

/// An artifact one provider signs under one capability.
pub trait SignedArtifact {
    /// The capability the signing provider must hold for this artifact.
    fn capability(&self) -> ProviderCapability;
    /// The provider the artifact names as its author.
    fn provider_id(&self) -> Identifier;
    /// Digest of the unsigned artifact; fails when the artifact is malformed.
    fn statement(&self) -> Result<Commitment, ProviderError>;
    fn signature(&self) -> &[u8];
    fn set_signature(&mut self, signature: Vec<u8>);
}

macro_rules! signed_artifact {
    ($type:ty, $capability:expr, $provider:ident) => {
        impl SignedArtifact for $type {
            fn capability(&self) -> ProviderCapability {
                $capability
            }

            fn provider_id(&self) -> Identifier {
                self.$provider
            }

            fn statement(&self) -> Result<Commitment, ProviderError> {
                <$type>::statement(self)
            }

            fn signature(&self) -> &[u8] {
                &self.signature
            }

            fn set_signature(&mut self, signature: Vec<u8>) {
                self.signature = signature;
            }
        }
    };
}

signed_artifact!(
    RegisterStream,
    ProviderCapability::StreamAttestor,
    attestor_provider_id
);
signed_artifact!(
    StreamTransition,
    ProviderCapability::StreamAttestor,
    attestor_provider_id
);
signed_artifact!(
    CreditDecision,
    ProviderCapability::CreditAssessor,
    provider_id
);
signed_artifact!(
    GuaranteeCommitment,
    ProviderCapability::Guarantor,
    provider_id
);
signed_artifact!(GuaranteeRelease, ProviderCapability::Guarantor, provider_id);
signed_artifact!(
    FundingQuote,
    ProviderCapability::LiquidityProvider,
    provider_id
);
signed_artifact!(
    DefaultAttestation,
    ProviderCapability::Servicer,
    provider_id
);
signed_artifact!(
    RegisterCredentialIssuer,
    ProviderCapability::CredentialIssuer,
    provider_id
);

/// Signs `artifact` with a provider's current artifact key and returns the
/// statement that was signed. The artifact is validated first, so a
/// malformed artifact is never signed.
pub fn sign_artifact<A: SignedArtifact>(
    artifact: &mut A,
    key: &SigningKey,
) -> Result<Commitment, ProviderError> {
    let statement = artifact.statement()?;
    artifact.set_signature(key.sign(&statement).to_bytes().to_vec());
    Ok(statement)
}

/// Read access to registered providers. The Aethel protocol book implements
/// this over its provider map; a host or a servicing book may implement it
/// over any view that agrees with the authoritative registration.
pub trait ProviderRegistry {
    fn provider(&self, provider_id: &Identifier) -> Option<&ProviderDefinition>;

    /// The provider, if it is registered and holds `capability` active at
    /// `now`. A registered provider without the capability is refused with
    /// [`ProviderError::MissingProviderCapability`], never silently upgraded.
    fn active_provider(
        &self,
        provider_id: &Identifier,
        capability: ProviderCapability,
        now: u64,
    ) -> Result<&ProviderDefinition, ProviderError> {
        let provider = self
            .provider(provider_id)
            .ok_or(ProviderError::UnknownProvider)?;
        if !provider.has(capability, now) {
            return Err(ProviderError::MissingProviderCapability);
        }
        Ok(provider)
    }

    /// Validates `artifact`, checks that its author holds the capability it
    /// needs at `now`, and verifies the signature under the author's current
    /// key. Returns the verified statement.
    fn verify_artifact<A: SignedArtifact>(
        &self,
        artifact: &A,
        now: u64,
    ) -> Result<Commitment, ProviderError> {
        let statement = artifact.statement()?;
        let provider = self.active_provider(&artifact.provider_id(), artifact.capability(), now)?;
        provider.verify_new_signature(&statement, artifact.signature())?;
        Ok(statement)
    }
}

/// The canonical registry shape: providers keyed by [`id_key`] of their id.
impl ProviderRegistry for BTreeMap<String, ProviderDefinition> {
    fn provider(&self, provider_id: &Identifier) -> Option<&ProviderDefinition> {
        self.get(&id_key(provider_id))
    }
}
