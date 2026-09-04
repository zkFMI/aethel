//! What a credential-issuer provider submits. The credentials, issuer keys,
//! revocation lists, and presentations are DeKYX objects; Aethel only records
//! which provider vouches for which DeKYX issuer key epoch.

use dekyx_core::{IssuerDefinition, RevocationStatusList};
use serde::{Deserialize, Serialize};

use aethel_types::{digest, Commitment, Identifier, ZERO};

use crate::ProviderError;

const CREDENTIAL_ISSUER_DOMAIN: &[u8] = b"AETHEL:CREDENTIAL-ISSUER:v1";
const CREDENTIAL_STATUS_DOMAIN: &[u8] = b"AETHEL:CREDENTIAL-STATUS:v1";

/// A credential-issuer provider vouching for one DeKYX issuer key epoch.
///
/// The DeKYX issuer id is the Aethel provider id, so a credential names its
/// vouching provider directly. The DeKYX signing key is separate from the
/// provider's artifact key and rotates independently of it: a rotation is a
/// second registration by the same provider with a higher epoch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterCredentialIssuer {
    pub operation_id: Identifier,
    pub provider_id: Identifier,
    pub issuer: IssuerDefinition,
    /// `None` for the first key epoch. For a rotation, the last instant at
    /// which credentials signed by earlier epochs stay acceptable; a value
    /// before their `valid_from` retires them immediately, which is the
    /// key-compromise path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_epochs_valid_until: Option<u64>,
    pub signature: Vec<u8>,
}

impl RegisterCredentialIssuer {
    pub fn statement(&self) -> Result<Commitment, ProviderError> {
        if self.operation_id == ZERO || self.issuer.issuer_id != self.provider_id {
            return Err(ProviderError::InvalidCredentialIssuer);
        }
        self.issuer.validate().map_err(ProviderError::Credential)?;
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        Ok(digest(CREDENTIAL_ISSUER_DOMAIN, &unsigned)?)
    }
}

/// An issuer-signed revocation status list for one DeKYX issuer key epoch.
/// Its authenticity is the issuer key's; Aethel adds only replay protection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublishCredentialStatus {
    pub operation_id: Identifier,
    pub status_list: RevocationStatusList,
}

impl PublishCredentialStatus {
    pub fn statement(&self) -> Result<Commitment, ProviderError> {
        if self.operation_id == ZERO {
            return Err(ProviderError::InvalidCredentialStatus);
        }
        self.status_list
            .statement_digest()
            .map_err(ProviderError::Credential)?;
        Ok(digest(CREDENTIAL_STATUS_DOMAIN, self)?)
    }
}
