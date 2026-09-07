use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use aethel_types::{
    digest, id_key, is_verifying_key, valid_window, Commitment, Identifier, MAX_UNIX_TIME, ZERO,
};

use crate::ProviderError;
use zkfmi_crypto::{
    hybrid::signature::HybridVerifier,
    key::{KeyPurpose, KeyRecord},
    suite::{Suite, SuiteId},
    traits::{Signer, Verifier},
};

/// The closed provider wire suite; both components are always required.
pub const PROVIDER_SIGNATURE_SUITE: Suite = Suite::new(SuiteId::Ed25519MlDsa65);

fn validate_artifact_key(key: &KeyRecord) -> Result<(), ProviderError> {
    key.validate()
        .map_err(|_| ProviderError::InvalidProviderKey)?;
    if key.suite != PROVIDER_SIGNATURE_SUITE
        || key.purpose != KeyPurpose::Attestation
        || key.rotation_proof.is_some()
    {
        return Err(ProviderError::InvalidProviderKey);
    }
    let classical = key.public_key[..32]
        .try_into()
        .map_err(|_| ProviderError::InvalidProviderKey)?;
    if !is_verifying_key(&classical) {
        return Err(ProviderError::InvalidProviderKey);
    }
    Ok(())
}

/// Lifecycle metadata is excluded so archived integrity survives retirement.
fn signature_message(
    provider_id: &Identifier,
    key: &KeyRecord,
    statement: &Commitment,
) -> Result<Commitment, ProviderError> {
    validate_artifact_key(key)?;
    let mut binding = key.clone();
    binding.revoked_at = None;
    binding.rotation_proof = None;
    Ok(digest(
        b"AETHEL:PROVIDER-HYBRID-ARTIFACT:v2",
        &(provider_id, binding, statement),
    )?)
}

/// Sign with an independently provisioned hybrid handle and enrolled metadata.
/// Never derive PQ secret material from a public classical key.
pub fn sign_provider_statement(
    signer: &dyn Signer,
    key: &KeyRecord,
    provider_id: &Identifier,
    statement: &Commitment,
) -> Result<Vec<u8>, ProviderError> {
    if signer.suite() != PROVIDER_SIGNATURE_SUITE || signer.public_key() != key.public_key {
        return Err(ProviderError::InvalidProviderKey);
    }
    let message = signature_message(provider_id, key, statement)?;
    signer
        .sign(KeyPurpose::Attestation, &message)
        .map_err(|_| ProviderError::InvalidSignature)
}

fn verify_signature(
    provider_id: &Identifier,
    key: &KeyRecord,
    statement: &Commitment,
    signature: &[u8],
) -> Result<(), ProviderError> {
    let message = signature_message(provider_id, key, statement)?;
    HybridVerifier
        .verify(
            KeyPurpose::Attestation,
            &key.public_key,
            &message,
            signature,
        )
        .map_err(|_| ProviderError::InvalidSignature)
}

const PROVIDER_DOMAIN: &[u8] = b"AETHEL:PROVIDER:v1";
const PROVIDER_KEY_ROTATION_DOMAIN: &[u8] = b"AETHEL:PROVIDER-KEY-ROTATION:v1";
const PROVIDER_STATUS_DOMAIN: &[u8] = b"AETHEL:PROVIDER-STATUS:v1";

/// Capabilities stay separate even when one institution implements several.
/// A credit score therefore never silently becomes a guarantee or a promise
/// to advance cash.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCapability {
    StreamAttestor,
    CreditAssessor,
    Guarantor,
    LiquidityProvider,
    Servicer,
    /// Vouches for a DeKYX issuer key (see `RegisterCredentialIssuer`) without
    /// becoming the credit assessor or guarantor for any line credentialed
    /// under it. The credentials themselves are DeKYX objects.
    CredentialIssuer,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    Active,
    Suspended,
    Revoked,
}

/// A key the provider signed with before a rotation. Artifacts recorded while
/// it was live stay verifiable against it; nothing new is accepted under it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetiredProviderKey {
    pub public_key: [u8; 32],
    pub artifact_key: KeyRecord,
    pub retired_at: u64,
}

/// One capability-bearing endpoint operated by a verified DeFMI participant.
///
/// `defmi_guarantor_id` links only the guarantee capability to DeFMI's
/// authoritative facility book.  It is deliberately optional for assessors,
/// credential issuers, stream attestors, liquidity providers, and servicers.
///
/// `public_key` is the key that signs new artifacts. `retired_keys` lists, in
/// rotation order, every earlier key; `sequence` counts rotations and status
/// changes so a control operation can name the exact state it expects.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderDefinition {
    pub provider_id: Identifier,
    pub participant_id: Identifier,
    pub capabilities: BTreeSet<ProviderCapability>,
    pub public_key: [u8; 32],
    pub artifact_key: KeyRecord,
    pub policy_registry_digest: Commitment,
    pub defmi_guarantor_id: Option<Identifier>,
    pub valid_from: u64,
    pub valid_until: u64,
    pub sequence: u64,
    pub status: ProviderStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retired_keys: Vec<RetiredProviderKey>,
}

impl ProviderDefinition {
    /// The registration form: sequence zero, active, and no key history.
    pub fn validate_initial(&self) -> Result<(), ProviderError> {
        if self.sequence != 0
            || self.status != ProviderStatus::Active
            || !self.retired_keys.is_empty()
            || self.artifact_key.key_version != 1
            || self.artifact_key.revoked_at.is_some()
            || self.artifact_key.rotation_proof.is_some()
        {
            return Err(ProviderError::InvalidProvider);
        }
        self.validate()
    }

    /// The stored form after any number of rotations and status changes.
    pub fn validate(&self) -> Result<(), ProviderError> {
        if [
            self.provider_id,
            self.participant_id,
            self.public_key,
            self.policy_registry_digest,
        ]
        .contains(&ZERO)
            || self.capabilities.is_empty()
            || !valid_window(self.valid_from, self.valid_until)
            || self.sequence < self.retired_keys.len() as u64
        {
            return Err(ProviderError::InvalidProvider);
        }
        if !is_verifying_key(&self.public_key) {
            return Err(ProviderError::InvalidProviderKey);
        }
        self.validate_key_binding(&self.artifact_key, &self.public_key)?;
        if self.artifact_key.key_version as usize != self.retired_keys.len() + 1 {
            return Err(ProviderError::InvalidProviderKey);
        }
        let mut keys = BTreeSet::from([self.public_key]);
        let mut pq_keys = BTreeSet::from([self.artifact_key.public_key[32..].to_vec()]);
        let mut key_ids = BTreeSet::from([self.artifact_key.key_id.clone()]);
        let mut last_retired_at = 0;
        for (index, retired) in self.retired_keys.iter().enumerate() {
            self.validate_key_binding(&retired.artifact_key, &retired.public_key)?;
            if !is_verifying_key(&retired.public_key) {
                return Err(ProviderError::InvalidProviderKey);
            }
            if retired.artifact_key.key_version as usize != index + 1
                || !pq_keys.insert(retired.artifact_key.public_key[32..].to_vec())
                || !key_ids.insert(retired.artifact_key.key_id.clone())
                || !keys.insert(retired.public_key)
                || retired.retired_at < last_retired_at
                || retired.retired_at == 0
                || retired.retired_at > MAX_UNIX_TIME
            {
                return Err(ProviderError::InvalidProvider);
            }
            last_retired_at = retired.retired_at;
        }
        match (
            self.capabilities.contains(&ProviderCapability::Guarantor),
            self.defmi_guarantor_id,
        ) {
            (true, Some(id)) if id != ZERO => Ok(()),
            (true, _) => Err(ProviderError::MissingGuaranteeAuthority),
            (false, Some(_)) => Err(ProviderError::InvalidProvider),
            (false, None) => Ok(()),
        }
    }

    pub fn has(&self, capability: ProviderCapability, now: u64) -> bool {
        self.status == ProviderStatus::Active
            && self.valid_from <= now
            && now <= self.valid_until
            && self.capabilities.contains(&capability)
    }

    /// The key the provider was registered with. An application that bound
    /// another identity record to that key at registration (DeFMI's guarantor
    /// record) compares against this rather than the rotating current key.
    pub fn registration_key(&self) -> [u8; 32] {
        self.retired_keys
            .first()
            .map_or(self.public_key, |retired| retired.public_key)
    }

    /// Every key that has ever been this provider's, newest last.
    pub fn signing_keys(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.retired_keys
            .iter()
            .map(|retired| retired.public_key)
            .chain(std::iter::once(self.public_key))
    }

    fn validate_key_binding(
        &self,
        key: &KeyRecord,
        classical: &[u8; 32],
    ) -> Result<(), ProviderError> {
        validate_artifact_key(key)?;
        if key.public_key[..32] != classical[..]
            || key.participant_id.as_str() != id_key(&self.participant_id)
        {
            return Err(ProviderError::InvalidProviderKey);
        }
        Ok(())
    }

    /// Only the current generation authorizes new work, at the host clock.
    pub fn verify_new_signature(
        &self,
        statement: &Commitment,
        signature: &[u8],
        now: u64,
    ) -> Result<(), ProviderError> {
        self.validate()?;
        if self.status != ProviderStatus::Active || now < self.valid_from || now > self.valid_until
        {
            return Err(ProviderError::MissingProviderCapability);
        }
        self.artifact_key
            .valid_at(now)
            .map_err(|_| ProviderError::InvalidProviderKey)?;
        verify_signature(&self.provider_id, &self.artifact_key, statement, signature)
    }

    /// Integrity verification for previously accepted state only. This never
    /// authorizes a new message or extends a key's operational validity.
    pub fn verify_recorded_signature(
        &self,
        statement: &Commitment,
        signature: &[u8],
    ) -> Result<(), ProviderError> {
        self.validate()?;
        for key in self
            .retired_keys
            .iter()
            .map(|retired| &retired.artifact_key)
            .chain(std::iter::once(&self.artifact_key))
        {
            if verify_signature(&self.provider_id, key, statement, signature).is_ok() {
                return Ok(());
            }
        }
        Err(ProviderError::InvalidSignature)
    }
}

/// Moves a provider to a new artifact-signing key. The request is signed by
/// the *next* key as proof of possession; the authority to rotate is the
/// application's (quorum approval and, in the Avalanche VM, equality with the
/// participant's governance-rotated quote key), exactly as for registration.
/// Artifacts already recorded under the retired key remain part of the book;
/// no new artifact is accepted under it from `rotated_at` on.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RotateProviderKey {
    pub operation_id: Identifier,
    pub provider_id: Identifier,
    pub next_public_key: [u8; 32],
    pub next_artifact_key: KeyRecord,
    pub expected_sequence: u64,
    pub rotated_at: u64,
    pub signature: Vec<u8>,
}

impl RotateProviderKey {
    pub fn statement(&self) -> Result<Commitment, ProviderError> {
        if [self.operation_id, self.provider_id, self.next_public_key].contains(&ZERO)
            || self.rotated_at == 0
            || self.rotated_at > MAX_UNIX_TIME
        {
            return Err(ProviderError::InvalidProvider);
        }
        if !is_verifying_key(&self.next_public_key) {
            return Err(ProviderError::InvalidProviderKey);
        }
        validate_artifact_key(&self.next_artifact_key)?;
        if self.next_artifact_key.public_key[..32] != self.next_public_key[..]
            || self.next_artifact_key.revoked_at.is_some()
            || self.next_artifact_key.rotation_proof.is_some()
        {
            return Err(ProviderError::InvalidProviderKey);
        }
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        Ok(digest(PROVIDER_KEY_ROTATION_DOMAIN, &unsigned)?)
    }

    /// Produce the next key's possession proof under the rotation purpose.
    pub fn sign_possession(&mut self, signer: &dyn Signer) -> Result<Commitment, ProviderError> {
        let statement = self.statement()?;
        if signer.suite() != PROVIDER_SIGNATURE_SUITE
            || signer.public_key() != self.next_artifact_key.public_key
        {
            return Err(ProviderError::InvalidProviderKey);
        }
        let message = signature_message(&self.provider_id, &self.next_artifact_key, &statement)?;
        self.signature = signer
            .sign(KeyPurpose::KeyRotation, &message)
            .map_err(|_| ProviderError::InvalidSignature)?;
        Ok(statement)
    }

    /// Proof of possession: the request must be signed by the next key.
    pub fn verify_possession(&self) -> Result<Commitment, ProviderError> {
        let statement = self.statement()?;
        self.next_artifact_key
            .valid_at(self.rotated_at)
            .map_err(|_| ProviderError::InvalidProviderKey)?;
        let message = signature_message(&self.provider_id, &self.next_artifact_key, &statement)?;
        HybridVerifier
            .verify(
                KeyPurpose::KeyRotation,
                &self.next_artifact_key.public_key,
                &message,
                &self.signature,
            )
            .map_err(|_| ProviderError::InvalidSignature)?;
        Ok(statement)
    }
}

/// Suspends, reinstates, or revokes a provider. Revocation is terminal. A
/// suspended or revoked provider signs nothing new; what it recorded while
/// active stays in the book.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetProviderStatus {
    pub operation_id: Identifier,
    pub provider_id: Identifier,
    pub status: ProviderStatus,
    pub expected_sequence: u64,
    pub effective_at: u64,
}

impl SetProviderStatus {
    pub fn statement(&self) -> Result<Commitment, ProviderError> {
        if [self.operation_id, self.provider_id].contains(&ZERO)
            || self.effective_at == 0
            || self.effective_at > MAX_UNIX_TIME
        {
            return Err(ProviderError::InvalidProvider);
        }
        Ok(digest(PROVIDER_STATUS_DOMAIN, self)?)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterProvider {
    pub operation_id: Identifier,
    pub provider: ProviderDefinition,
}

impl RegisterProvider {
    pub fn statement(&self) -> Result<Commitment, ProviderError> {
        if self.operation_id == ZERO {
            return Err(ProviderError::InvalidProvider);
        }
        self.provider.validate_initial()?;
        Ok(digest(PROVIDER_DOMAIN, self)?)
    }
}
