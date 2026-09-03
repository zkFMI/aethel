use std::collections::BTreeSet;

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::{digest, valid_window, AethelError, Commitment, Identifier, MAX_UNIX_TIME, ZERO};

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
    pub fn validate_initial(&self) -> Result<(), AethelError> {
        if self.sequence != 0
            || self.status != ProviderStatus::Active
            || !self.retired_keys.is_empty()
        {
            return Err(AethelError::InvalidProvider);
        }
        self.validate()
    }

    /// The stored form after any number of rotations and status changes.
    pub fn validate(&self) -> Result<(), AethelError> {
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
            return Err(AethelError::InvalidProvider);
        }
        VerifyingKey::from_bytes(&self.public_key).map_err(|_| AethelError::InvalidProviderKey)?;
        let mut keys = BTreeSet::from([self.public_key]);
        let mut last_retired_at = 0;
        for retired in &self.retired_keys {
            VerifyingKey::from_bytes(&retired.public_key)
                .map_err(|_| AethelError::InvalidProviderKey)?;
            if !keys.insert(retired.public_key)
                || retired.retired_at < last_retired_at
                || retired.retired_at == 0
                || retired.retired_at > MAX_UNIX_TIME
            {
                return Err(AethelError::InvalidProvider);
            }
            last_retired_at = retired.retired_at;
        }
        match (
            self.capabilities.contains(&ProviderCapability::Guarantor),
            self.defmi_guarantor_id,
        ) {
            (true, Some(id)) if id != ZERO => Ok(()),
            (true, _) => Err(AethelError::MissingGuaranteeAuthority),
            (false, Some(_)) => Err(AethelError::InvalidProvider),
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
    pub expected_sequence: u64,
    pub rotated_at: u64,
    pub signature: Vec<u8>,
}

impl RotateProviderKey {
    pub fn statement(&self) -> Result<Commitment, AethelError> {
        if [self.operation_id, self.provider_id, self.next_public_key].contains(&ZERO)
            || self.rotated_at == 0
            || self.rotated_at > MAX_UNIX_TIME
        {
            return Err(AethelError::InvalidProvider);
        }
        VerifyingKey::from_bytes(&self.next_public_key)
            .map_err(|_| AethelError::InvalidProviderKey)?;
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        digest(PROVIDER_KEY_ROTATION_DOMAIN, &unsigned)
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
    pub fn statement(&self) -> Result<Commitment, AethelError> {
        if [self.operation_id, self.provider_id].contains(&ZERO)
            || self.effective_at == 0
            || self.effective_at > MAX_UNIX_TIME
        {
            return Err(AethelError::InvalidProvider);
        }
        digest(PROVIDER_STATUS_DOMAIN, self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterProvider {
    pub operation_id: Identifier,
    pub provider: ProviderDefinition,
}

impl RegisterProvider {
    pub fn statement(&self) -> Result<Commitment, AethelError> {
        if self.operation_id == ZERO {
            return Err(AethelError::InvalidProvider);
        }
        self.provider.validate_initial()?;
        digest(PROVIDER_DOMAIN, self)
    }
}
