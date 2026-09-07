use std::collections::{BTreeMap, BTreeSet};

use dekyx_aethel::AethelDeKyxAdapter;
use dekyx_core::{
    AnonymousPresentation, DeKyxError, IssuerDirectory, PresentationContext, PresentationLedger,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use aethel_provider_sdk::{ProviderError, ProviderRegistry};

use crate::{
    digest, id_key, subject::binding_is_well_formed, ConfidentialArtifact,
    ConfidentialSubjectBinding, CreditDecision, DefaultAttestation, FundingQuote, GuaranteeClaim,
    GuaranteeCommitment, GuaranteeRelease, GuaranteeStatus, Identifier, ProviderCapability,
    ProviderDefinition, ProviderStatus, PublishCredentialStatus, ReceivableIssuance,
    ReceivableSeries, ReceivableStatus, RegisterCredentialIssuer, RegisterProvider, RegisterSeries,
    RegisterStream, RetiredProviderKey, RotateProviderKey, SetProviderStatus, StreamState,
    StreamTransition, ZERO,
};

const BOOK_DOMAIN: &[u8] = b"AETHEL:BOOK:v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisteredStream {
    pub attestor_provider_id: Identifier,
    pub state: StreamState,
}

/// Canonical Aethel protocol state.  Asset title and money remain in DeFMI;
/// this book stores only streaming-receivable semantics and cross-layer IDs.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AethelBook {
    pub providers: BTreeMap<String, ProviderDefinition>,
    pub streams: BTreeMap<String, RegisteredStream>,
    pub series: BTreeMap<String, ReceivableSeries>,
    /// DeKYX issuer key epochs and revocation lists vouched for by
    /// credential-issuer providers. Owned by DeKYX; Aethel only persists it.
    #[serde(default, skip_serializing_if = "IssuerDirectory::is_empty")]
    pub credential_issuers: IssuerDirectory,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub confidential_subjects: BTreeMap<String, ConfidentialSubjectBinding>,
    pub credit_decisions: BTreeMap<String, CreditDecision>,
    pub guarantees: BTreeMap<String, GuaranteeCommitment>,
    pub funding_quotes: BTreeMap<String, FundingQuote>,
    pub issuances: BTreeMap<String, ReceivableIssuance>,
    pub default_attestations: BTreeMap<String, DefaultAttestation>,
    pub guarantee_claims: BTreeMap<String, GuaranteeClaim>,
    /// Guarantor-signed withdrawals of unbound guarantees, keyed by guarantee.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub guarantee_releases: BTreeMap<String, GuaranteeRelease>,
    pub used_operations: BTreeSet<String>,
    pub used_provider_nonces: BTreeSet<String>,
    pub used_allocation_nullifiers: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub used_subject_nullifiers: BTreeSet<String>,
    /// DeKYX replay ledger: one presentation context per scope pseudonym.
    #[serde(default, skip_serializing_if = "PresentationLedger::is_empty")]
    pub consumed_presentations: PresentationLedger,
}

impl AethelBook {
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
            && self.streams.is_empty()
            && self.series.is_empty()
            && self.confidential_subjects.is_empty()
            && self.credit_decisions.is_empty()
            && self.guarantees.is_empty()
            && self.funding_quotes.is_empty()
            && self.issuances.is_empty()
            && self.default_attestations.is_empty()
            && self.guarantee_claims.is_empty()
            && self.guarantee_releases.is_empty()
            && self.used_operations.is_empty()
            && self.used_provider_nonces.is_empty()
            && self.used_allocation_nullifiers.is_empty()
            && self.used_subject_nullifiers.is_empty()
            && self.credential_issuers.is_empty()
            && self.consumed_presentations.is_empty()
    }

    pub fn confidential_subject(
        &self,
        request_id: &Identifier,
    ) -> Option<&ConfidentialSubjectBinding> {
        self.confidential_subjects.get(&id_key(request_id))
    }

    pub fn root(&self) -> Result<[u8; 32], AethelError> {
        self.validate()?;
        digest(BOOK_DOMAIN, self)
    }

    pub fn provider(&self, provider_id: &Identifier) -> Result<&ProviderDefinition, AethelError> {
        self.providers
            .get(&id_key(provider_id))
            .ok_or(AethelError::UnknownProvider)
    }

    pub fn stream(&self, stream_id: &Identifier) -> Result<&RegisteredStream, AethelError> {
        self.streams
            .get(&id_key(stream_id))
            .ok_or(AethelError::UnknownStream)
    }

    pub fn register_provider(
        &mut self,
        request: RegisterProvider,
        now: u64,
    ) -> Result<[u8; 32], AethelError> {
        let statement = request.statement()?;
        if now < request.provider.valid_from || now > request.provider.valid_until {
            return Err(AethelError::OutsideValidityWindow);
        }
        request
            .provider
            .artifact_key
            .valid_at(now)
            .map_err(|_| AethelError::InvalidProviderKey)?;
        let key = id_key(&request.provider.provider_id);
        if self.providers.contains_key(&key) {
            return Err(AethelError::DuplicateProvider);
        }
        self.consume_operation(&request.operation_id)?;
        self.providers.insert(key, request.provider);
        Ok(statement)
    }

    /// Retires the provider's current artifact key and installs the next one.
    /// The request proves possession of the next key; whether this provider
    /// may rotate at all is the application's decision (the VM ties it to the
    /// participant's governance-rotated quote key). Artifacts already recorded
    /// under the retired key stay in the book; it signs nothing new.
    pub fn rotate_provider_key(
        &mut self,
        request: RotateProviderKey,
        now: u64,
    ) -> Result<[u8; 32], AethelError> {
        let statement = request.verify_possession()?;
        self.ensure_operation_unused(&request.operation_id)?;
        let provider = self.provider(&request.provider_id)?;
        provider.validate()?;
        if provider.status == ProviderStatus::Revoked {
            return Err(AethelError::ProviderRevoked);
        }
        if request.rotated_at != now || now < provider.valid_from || now > provider.valid_until {
            return Err(AethelError::OutsideValidityWindow);
        }
        if provider.sequence != request.expected_sequence {
            return Err(AethelError::StaleSequence);
        }
        if provider
            .signing_keys()
            .any(|key| key == request.next_public_key)
            || request.next_artifact_key.key_version
                != provider
                    .artifact_key
                    .key_version
                    .checked_add(1)
                    .ok_or(AethelError::ArithmeticOverflow)?
            || request.next_artifact_key.participant_id != provider.artifact_key.participant_id
            || provider
                .retired_keys
                .iter()
                .map(|key| &key.artifact_key)
                .chain(std::iter::once(&provider.artifact_key))
                .any(|key| {
                    key.key_id == request.next_artifact_key.key_id
                        || key.public_key[32..] == request.next_artifact_key.public_key[32..]
                })
        {
            return Err(AethelError::InvalidProviderKey);
        }
        // Validate the complete successor before changing persisted state.
        let mut successor = provider.clone();
        successor.retired_keys.push(RetiredProviderKey {
            public_key: successor.public_key,
            artifact_key: successor.artifact_key.clone(),
            retired_at: now,
        });
        successor.public_key = request.next_public_key;
        successor.artifact_key = request.next_artifact_key;
        successor.sequence = successor
            .sequence
            .checked_add(1)
            .ok_or(AethelError::ArithmeticOverflow)?;
        successor.validate()?;
        self.providers
            .insert(id_key(&request.provider_id), successor);
        self.consume_operation(&request.operation_id)?;
        Ok(statement)
    }

    /// Suspends, reinstates, or revokes a provider. Revocation is terminal.
    /// Nothing already recorded is removed: a suspended or revoked provider's
    /// past artifacts stay verifiable, and it can sign no new ones.
    pub fn set_provider_status(
        &mut self,
        request: SetProviderStatus,
        now: u64,
    ) -> Result<[u8; 32], AethelError> {
        let statement = request.statement()?;
        self.ensure_operation_unused(&request.operation_id)?;
        let provider = self.provider(&request.provider_id)?;
        if provider.status == ProviderStatus::Revoked {
            return Err(AethelError::ProviderRevoked);
        }
        if request.effective_at != now {
            return Err(AethelError::OutsideValidityWindow);
        }
        if provider.sequence != request.expected_sequence {
            return Err(AethelError::StaleSequence);
        }
        if provider.status == request.status {
            return Err(AethelError::InvalidProvider);
        }
        let provider = self
            .providers
            .get_mut(&id_key(&request.provider_id))
            .expect("checked provider");
        provider.status = request.status;
        provider.sequence = provider
            .sequence
            .checked_add(1)
            .ok_or(AethelError::ArithmeticOverflow)?;
        self.consume_operation(&request.operation_id)?;
        Ok(statement)
    }

    pub fn register_stream(
        &mut self,
        request: RegisterStream,
        now: u64,
    ) -> Result<[u8; 32], AethelError> {
        let statement = request.statement()?;
        let provider = self.active_provider(
            &request.attestor_provider_id,
            ProviderCapability::StreamAttestor,
            now,
        )?;
        provider.verify_new_signature(&statement, &request.signature, now)?;
        let key = id_key(&request.state.stream_id);
        if self.streams.contains_key(&key) {
            return Err(AethelError::DuplicateStream);
        }
        self.ensure_operation_unused(&request.operation_id)?;
        self.streams.insert(
            key,
            RegisteredStream {
                attestor_provider_id: request.attestor_provider_id,
                state: request.state,
            },
        );
        self.consume_operation(&request.operation_id)?;
        Ok(statement)
    }

    pub fn transition_stream(
        &mut self,
        request: StreamTransition,
        now: u64,
    ) -> Result<[u8; 32], AethelError> {
        let statement = request.statement()?;
        let provider = self.active_provider(
            &request.attestor_provider_id,
            ProviderCapability::StreamAttestor,
            now,
        )?;
        provider.verify_new_signature(&statement, &request.signature, now)?;
        self.ensure_operation_unused(&request.operation_id)?;
        let key = id_key(&request.after_state.stream_id);
        let current = self.streams.get(&key).ok_or(AethelError::UnknownStream)?;
        if current.attestor_provider_id != request.attestor_provider_id
            || current.state.root()? != request.before_state_root
            || !current.state.valid_source_successor(&request.after_state)
        {
            return Err(AethelError::InvalidStreamTransition);
        }
        self.streams.get_mut(&key).expect("checked stream").state = request.after_state;
        self.consume_operation(&request.operation_id)?;
        Ok(statement)
    }

    pub fn register_series(
        &mut self,
        request: RegisterSeries,
        now: u64,
    ) -> Result<[u8; 32], AethelError> {
        let statement = request.statement()?;
        let stream = self.stream(&request.series.stream_id)?;
        if stream.state.settlement_asset_id == request.series.receivable_asset_id
            || now < request.series.valid_from
            || now > request.series.maturity
        {
            return Err(AethelError::InvalidSeries);
        }
        let key = id_key(&request.series.series_id);
        if self.series.contains_key(&key)
            || self
                .series
                .values()
                .any(|series| series.receivable_asset_id == request.series.receivable_asset_id)
        {
            return Err(AethelError::DuplicateSeries);
        }
        self.consume_operation(&request.operation_id)?;
        self.series.insert(key, request.series);
        Ok(statement)
    }

    pub fn record_credit_decision(
        &mut self,
        decision: CreditDecision,
        now: u64,
    ) -> Result<[u8; 32], AethelError> {
        let statement = decision.statement()?;
        let provider = self.active_provider(
            &decision.provider_id,
            ProviderCapability::CreditAssessor,
            now,
        )?;
        provider.verify_new_signature(&statement, &decision.signature, now)?;
        self.ensure_series_state(
            &decision.series_id,
            decision.stream_state_version,
            decision.stream_state_root,
            now,
        )?;
        if decision.valid_until < now
            || decision.valid_until > provider.valid_until
            || decision.valid_until > self.series(&decision.series_id)?.maturity
        {
            return Err(AethelError::OutsideValidityWindow);
        }
        self.validate_credit_subject_binding(&decision)?;
        self.ensure_artifact_ids_unused(
            &decision.operation_id,
            &decision.provider_id,
            &decision.nonce,
            &decision.decision_id,
            &self.credit_decisions,
        )?;
        self.credit_decisions
            .insert(id_key(&decision.decision_id), decision.clone());
        self.consume_provider_artifact(
            &decision.operation_id,
            &decision.provider_id,
            &decision.nonce,
        )?;
        Ok(statement)
    }

    /// Records the DeKYX issuer key a credential-issuer provider vouches for,
    /// or rotates that provider's issuer key to a higher epoch.
    pub fn register_credential_issuer(
        &mut self,
        request: RegisterCredentialIssuer,
        now: u64,
    ) -> Result<[u8; 32], AethelError> {
        let statement = request.statement()?;
        let provider = self.active_provider(
            &request.provider_id,
            ProviderCapability::CredentialIssuer,
            now,
        )?;
        provider.verify_new_signature(&statement, &request.signature, now)?;
        if request.issuer.valid_from < provider.valid_from
            || request.issuer.valid_until > provider.valid_until
        {
            return Err(AethelError::OutsideValidityWindow);
        }
        self.ensure_operation_unused(&request.operation_id)?;
        let already_registered = self
            .credential_issuers
            .registry()
            .definitions()
            .any(|issuer| issuer.issuer_id == request.provider_id);
        match (already_registered, request.previous_epochs_valid_until) {
            (false, None) => self
                .credential_issuers
                .register_issuer(request.issuer)
                .map_err(AethelError::Credential)?,
            (true, Some(previous_valid_until)) => self
                .credential_issuers
                .rotate_key(request.issuer, previous_valid_until)
                .map_err(AethelError::Credential)?,
            _ => return Err(AethelError::InvalidCredentialIssuer),
        }
        self.consume_operation(&request.operation_id)?;
        Ok(statement)
    }

    /// Accepts an issuer-signed revocation status list for a registered DeKYX
    /// issuer key epoch. DeKYX enforces the signature and monotone status epoch.
    pub fn publish_credential_status(
        &mut self,
        request: PublishCredentialStatus,
        now: u64,
    ) -> Result<[u8; 32], AethelError> {
        let statement = request.statement()?;
        self.ensure_operation_unused(&request.operation_id)?;
        if request.status_list.effective_at > now {
            return Err(AethelError::OutsideValidityWindow);
        }
        self.credential_issuers
            .publish_status_list(request.status_list)
            .map_err(AethelError::Credential)?;
        self.consume_operation(&request.operation_id)?;
        Ok(statement)
    }

    /// Exact DeKYX context a holder must present against for `artifact`.
    pub fn presentation_context(
        &self,
        artifact: ConfidentialArtifact<'_>,
    ) -> Result<PresentationContext, AethelError> {
        artifact.presentation_context(self.series(&artifact.series_id())?)
    }

    /// Atomically verifies the holder's DeKYX presentation for this exact
    /// decision, binds or matches the anonymous line, and records the
    /// provider-signed credit decision that uses it.
    pub fn record_confidential_credit_decision(
        &mut self,
        presentation: &AnonymousPresentation,
        decision: CreditDecision,
        now: u64,
    ) -> Result<[u8; 32], AethelError> {
        let mut next = self.clone();
        let binding = next.verify_subject_presentation(
            presentation,
            ConfidentialArtifact::CreditDecision(&decision),
            now,
        )?;
        next.bind_or_match_confidential_subject(binding, now)?;
        let statement = next.record_credit_decision(decision, now)?;
        *self = next;
        Ok(statement)
    }

    pub fn record_guarantee(
        &mut self,
        guarantee: GuaranteeCommitment,
        now: u64,
    ) -> Result<[u8; 32], AethelError> {
        let statement = guarantee.statement()?;
        let provider =
            self.active_provider(&guarantee.provider_id, ProviderCapability::Guarantor, now)?;
        provider.verify_new_signature(&statement, &guarantee.signature, now)?;
        self.ensure_series_state(
            &guarantee.series_id,
            guarantee.stream_state_version,
            guarantee.stream_state_root,
            now,
        )?;
        if guarantee.valid_until < now
            || guarantee.valid_until > provider.valid_until
            || guarantee.valid_until > self.series(&guarantee.series_id)?.maturity
            || self
                .guarantees
                .values()
                .any(|existing| existing.defmi_hold_id == guarantee.defmi_hold_id)
        {
            return Err(AethelError::InvalidGuarantee);
        }
        if let Some(decision_id) = guarantee.credit_decision_id {
            let decision = self.decision(&decision_id)?;
            if !same_request_state(
                decision.request_id,
                decision.series_id,
                decision.stream_state_version,
                decision.stream_state_root,
                guarantee.request_id,
                guarantee.series_id,
                guarantee.stream_state_version,
                guarantee.stream_state_root,
            ) || decision.valid_until < now
            {
                return Err(AethelError::MismatchedArtifact);
            }
        }
        self.validate_guarantee_subject_binding(&guarantee)?;
        self.ensure_artifact_ids_unused(
            &guarantee.operation_id,
            &guarantee.provider_id,
            &guarantee.nonce,
            &guarantee.guarantee_id,
            &self.guarantees,
        )?;
        self.guarantees
            .insert(id_key(&guarantee.guarantee_id), guarantee.clone());
        self.consume_provider_artifact(
            &guarantee.operation_id,
            &guarantee.provider_id,
            &guarantee.nonce,
        )?;
        Ok(statement)
    }

    /// Atomically binds a guarantee to the same anonymous line as its credit
    /// decision, using a fresh DeKYX presentation for this exact guarantee.
    pub fn record_confidential_guarantee(
        &mut self,
        presentation: &AnonymousPresentation,
        guarantee: GuaranteeCommitment,
        now: u64,
    ) -> Result<[u8; 32], AethelError> {
        let mut next = self.clone();
        let binding = next.verify_subject_presentation(
            presentation,
            ConfidentialArtifact::Guarantee(&guarantee),
            now,
        )?;
        next.bind_or_match_confidential_subject(binding, now)?;
        let statement = next.record_guarantee(guarantee, now)?;
        *self = next;
        Ok(statement)
    }

    /// The guarantor withdraws a guarantee that no issuance has bound. A bound
    /// guarantee covers a live note and can only end through a claim.
    pub fn release_guarantee(
        &mut self,
        release: GuaranteeRelease,
        now: u64,
    ) -> Result<[u8; 32], AethelError> {
        let statement = release.statement()?;
        let provider =
            self.active_provider(&release.provider_id, ProviderCapability::Guarantor, now)?;
        provider.verify_new_signature(&statement, &release.signature, now)?;
        if release.released_at != now {
            return Err(AethelError::InvalidGuaranteeRelease);
        }
        self.ensure_operation_unused(&release.operation_id)?;
        let guarantee = self.guarantee(&release.guarantee_id)?;
        if guarantee.provider_id != release.provider_id
            || guarantee.status != GuaranteeStatus::Available
            || guarantee.bound_issuance_id.is_some()
        {
            return Err(AethelError::GuaranteeUnavailable);
        }
        let key = id_key(&release.guarantee_id);
        if self.guarantee_releases.contains_key(&key) {
            return Err(AethelError::Replay);
        }
        self.guarantees
            .get_mut(&key)
            .expect("checked guarantee")
            .status = GuaranteeStatus::Released;
        self.guarantee_releases.insert(key, release.clone());
        self.consume_operation(&release.operation_id)?;
        Ok(statement)
    }

    pub fn record_funding_quote(
        &mut self,
        quote: FundingQuote,
        now: u64,
    ) -> Result<[u8; 32], AethelError> {
        let statement = quote.statement()?;
        let provider = self.active_provider(
            &quote.provider_id,
            ProviderCapability::LiquidityProvider,
            now,
        )?;
        provider.verify_new_signature(&statement, &quote.signature, now)?;
        let stream = self.ensure_series_state(
            &quote.series_id,
            quote.stream_state_version,
            quote.stream_state_root,
            now,
        )?;
        if quote.cash_asset_id != stream.state.settlement_asset_id
            || quote.valid_until < now
            || quote.valid_until > provider.valid_until
            || quote.valid_until > self.series(&quote.series_id)?.maturity
            || self
                .funding_quotes
                .values()
                .any(|existing| existing.cash_reservation_id == quote.cash_reservation_id)
        {
            return Err(AethelError::InvalidFundingQuote);
        }
        if let Some(decision_id) = quote.credit_decision_id {
            let decision = self.decision(&decision_id)?;
            if !same_request_state(
                decision.request_id,
                decision.series_id,
                decision.stream_state_version,
                decision.stream_state_root,
                quote.request_id,
                quote.series_id,
                quote.stream_state_version,
                quote.stream_state_root,
            ) || decision.valid_until < now
            {
                return Err(AethelError::MismatchedArtifact);
            }
        }
        if let Some(guarantee_id) = quote.guarantee_id {
            let guarantee = self.guarantee(&guarantee_id)?;
            if !same_request_state(
                guarantee.request_id,
                guarantee.series_id,
                guarantee.stream_state_version,
                guarantee.stream_state_root,
                quote.request_id,
                quote.series_id,
                quote.stream_state_version,
                quote.stream_state_root,
            ) || guarantee.status != GuaranteeStatus::Available
                || guarantee.valid_until < now
            {
                return Err(AethelError::MismatchedArtifact);
            }
        }
        self.ensure_artifact_ids_unused(
            &quote.operation_id,
            &quote.provider_id,
            &quote.nonce,
            &quote.quote_id,
            &self.funding_quotes,
        )?;
        self.funding_quotes
            .insert(id_key(&quote.quote_id), quote.clone());
        self.consume_provider_artifact(&quote.operation_id, &quote.provider_id, &quote.nonce)?;
        Ok(statement)
    }

    pub fn issue_receivable(
        &mut self,
        issuance: ReceivableIssuance,
        now: u64,
    ) -> Result<[u8; 32], AethelError> {
        let statement = issuance.statement()?;
        if issuance.issued_at != now {
            return Err(AethelError::InvalidIssuance);
        }
        self.ensure_operation_unused(&issuance.operation_id)?;
        if self.issuances.contains_key(&id_key(&issuance.issuance_id))
            || self
                .issuances
                .values()
                .any(|existing| existing.note_id == issuance.note_id)
            || self
                .used_allocation_nullifiers
                .contains(&id_key(&issuance.allocation_nullifier))
        {
            return Err(AethelError::DuplicateIssuance);
        }
        let series = self.series(&issuance.series_id)?.clone();
        if series.status != ReceivableStatus::Active || now > series.maturity {
            return Err(AethelError::SeriesUnavailable);
        }
        let stream_key = id_key(&series.stream_id);
        let stream = self
            .streams
            .get(&stream_key)
            .ok_or(AethelError::UnknownStream)?;
        if stream.state.version != issuance.before_stream_state_version
            || stream.state.root()? != issuance.before_stream_state_root
        {
            return Err(AethelError::StaleStreamState);
        }
        self.validate_issuance_artifacts(&issuance, &series, now)?;

        let next_state = stream
            .state
            .valid_issuance_successor(issuance.after_pledged_commitment)?;
        self.streams
            .get_mut(&stream_key)
            .expect("checked stream")
            .state = next_state;
        if let Some(guarantee_id) = issuance.guarantee_id {
            let guarantee = self
                .guarantees
                .get_mut(&id_key(&guarantee_id))
                .expect("validated guarantee");
            guarantee.status = GuaranteeStatus::Bound;
            guarantee.bound_issuance_id = Some(issuance.issuance_id);
        }
        if let Some(quote_id) = issuance.funding_quote_id {
            self.funding_quotes
                .get_mut(&id_key(&quote_id))
                .expect("validated funding quote")
                .bound_issuance_id = Some(issuance.issuance_id);
        }
        self.used_allocation_nullifiers
            .insert(id_key(&issuance.allocation_nullifier));
        self.issuances
            .insert(id_key(&issuance.issuance_id), issuance.clone());
        self.consume_operation(&issuance.operation_id)?;
        Ok(statement)
    }

    pub fn record_default(
        &mut self,
        attestation: DefaultAttestation,
        now: u64,
    ) -> Result<[u8; 32], AethelError> {
        let statement = attestation.statement()?;
        let provider =
            self.active_provider(&attestation.provider_id, ProviderCapability::Servicer, now)?;
        provider.verify_new_signature(&statement, &attestation.signature, now)?;
        let stream = self.stream(&attestation.stream_id)?;
        if stream.state.version != attestation.stream_state_version
            || stream.state.root()? != attestation.stream_state_root
            || stream.state.status != crate::StreamStatus::Defaulted
            || attestation.observed_at > now
        {
            return Err(AethelError::InvalidDefaultAttestation);
        }
        self.ensure_artifact_ids_unused(
            &attestation.operation_id,
            &attestation.provider_id,
            &attestation.attestation_id,
            &attestation.attestation_id,
            &self.default_attestations,
        )?;
        self.default_attestations
            .insert(id_key(&attestation.attestation_id), attestation.clone());
        self.consume_provider_artifact(
            &attestation.operation_id,
            &attestation.provider_id,
            &attestation.attestation_id,
        )?;
        Ok(statement)
    }

    pub fn claim_guarantee(
        &mut self,
        claim: GuaranteeClaim,
        now: u64,
    ) -> Result<[u8; 32], AethelError> {
        let statement = claim.statement()?;
        if claim.claimed_at != now || self.guarantee_claims.contains_key(&id_key(&claim.claim_id)) {
            return Err(AethelError::InvalidGuaranteeClaim);
        }
        self.ensure_operation_unused(&claim.operation_id)?;
        let guarantee = self.guarantee(&claim.guarantee_id)?;
        if guarantee.status != GuaranteeStatus::Bound
            || guarantee.bound_issuance_id != Some(claim.issuance_id)
            || guarantee.valid_until < now
        {
            return Err(AethelError::GuaranteeUnavailable);
        }
        let issuance = self
            .issuances
            .get(&id_key(&claim.issuance_id))
            .ok_or(AethelError::UnknownIssuance)?;
        let series = self.series(&issuance.series_id)?;
        let default = self
            .default_attestations
            .get(&id_key(&claim.default_attestation_id))
            .ok_or(AethelError::UnknownDefaultAttestation)?;
        if default.stream_id != series.stream_id {
            return Err(AethelError::MismatchedArtifact);
        }
        self.guarantees
            .get_mut(&id_key(&claim.guarantee_id))
            .expect("checked guarantee")
            .status = GuaranteeStatus::Claimed;
        self.guarantee_claims
            .insert(id_key(&claim.claim_id), claim.clone());
        self.consume_operation(&claim.operation_id)?;
        Ok(statement)
    }

    pub fn validate(&self) -> Result<(), AethelError> {
        for (key, provider) in &self.providers {
            provider.validate()?;
            if key != &id_key(&provider.provider_id) {
                return Err(AethelError::InvalidState);
            }
        }
        for (key, stream) in &self.streams {
            stream.state.validate()?;
            let provider = self.provider(&stream.attestor_provider_id)?;
            if key != &id_key(&stream.state.stream_id)
                || !provider
                    .capabilities
                    .contains(&ProviderCapability::StreamAttestor)
            {
                return Err(AethelError::InvalidState);
            }
        }
        let mut series_assets = BTreeSet::new();
        for (key, series) in &self.series {
            series.validate_initial()?;
            if key != &id_key(&series.series_id)
                || !self.streams.contains_key(&id_key(&series.stream_id))
                || !series_assets.insert(series.receivable_asset_id)
            {
                return Err(AethelError::InvalidState);
            }
        }
        let mut subject_nullifiers = BTreeSet::new();
        for (key, binding) in &self.confidential_subjects {
            if !binding_is_well_formed(binding) {
                return Err(AethelError::InvalidConfidentialSubject);
            }
            let issuer = self.provider(&binding.issuer_provider_id)?;
            self.credential_issuers
                .issuer(&binding.issuer_provider_id, binding.issuer_key_epoch)
                .map_err(|_| AethelError::InvalidState)?;
            if key != &id_key(&binding.request_id)
                || !issuer
                    .capabilities
                    .contains(&ProviderCapability::CredentialIssuer)
                || !subject_nullifiers.insert(id_key(&binding.subject_nullifier))
                || (!self
                    .credit_decisions
                    .values()
                    .any(|decision| decision.request_id == binding.request_id)
                    && !self
                        .guarantees
                        .values()
                        .any(|guarantee| guarantee.request_id == binding.request_id))
            {
                return Err(AethelError::InvalidState);
            }
        }
        if subject_nullifiers != self.used_subject_nullifiers {
            return Err(AethelError::InvalidState);
        }
        for (key, decision) in &self.credit_decisions {
            let statement = decision.statement()?;
            let provider = self.provider(&decision.provider_id)?;
            provider.verify_recorded_signature(&statement, &decision.signature)?;
            if key != &id_key(&decision.decision_id)
                || !self.series.contains_key(&id_key(&decision.series_id))
                || !provider
                    .capabilities
                    .contains(&ProviderCapability::CreditAssessor)
            {
                return Err(AethelError::InvalidState);
            }
            self.validate_credit_subject_binding(decision)?;
        }
        for (key, guarantee) in &self.guarantees {
            let mut initial = guarantee.clone();
            initial.status = GuaranteeStatus::Available;
            initial.bound_issuance_id = None;
            let statement = initial.statement()?;
            let provider = self.provider(&guarantee.provider_id)?;
            provider.verify_recorded_signature(&statement, &guarantee.signature)?;
            let released = self.guarantee_releases.contains_key(key);
            if key != &id_key(&guarantee.guarantee_id)
                || !provider
                    .capabilities
                    .contains(&ProviderCapability::Guarantor)
                || !self.series.contains_key(&id_key(&guarantee.series_id))
                || (matches!(
                    guarantee.status,
                    GuaranteeStatus::Available | GuaranteeStatus::Released
                ) && guarantee.bound_issuance_id.is_some())
                || (matches!(
                    guarantee.status,
                    GuaranteeStatus::Bound | GuaranteeStatus::Claimed
                ) && guarantee.bound_issuance_id.is_none())
                || released != (guarantee.status == GuaranteeStatus::Released)
            {
                return Err(AethelError::InvalidState);
            }
            if let Some(decision_id) = guarantee.credit_decision_id {
                let decision = self
                    .credit_decisions
                    .get(&id_key(&decision_id))
                    .ok_or(AethelError::InvalidState)?;
                if !same_request_state(
                    decision.request_id,
                    decision.series_id,
                    decision.stream_state_version,
                    decision.stream_state_root,
                    guarantee.request_id,
                    guarantee.series_id,
                    guarantee.stream_state_version,
                    guarantee.stream_state_root,
                ) {
                    return Err(AethelError::InvalidState);
                }
            }
            self.validate_guarantee_subject_binding(guarantee)?;
        }
        for (key, quote) in &self.funding_quotes {
            let mut initial = quote.clone();
            initial.bound_issuance_id = None;
            let statement = initial.statement()?;
            let provider = self.provider(&quote.provider_id)?;
            provider.verify_recorded_signature(&statement, &quote.signature)?;
            if key != &id_key(&quote.quote_id)
                || !self.series.contains_key(&id_key(&quote.series_id))
                || !provider
                    .capabilities
                    .contains(&ProviderCapability::LiquidityProvider)
            {
                return Err(AethelError::InvalidState);
            }
            if let Some(decision_id) = quote.credit_decision_id {
                let decision = self
                    .credit_decisions
                    .get(&id_key(&decision_id))
                    .ok_or(AethelError::InvalidState)?;
                if !same_request_state(
                    decision.request_id,
                    decision.series_id,
                    decision.stream_state_version,
                    decision.stream_state_root,
                    quote.request_id,
                    quote.series_id,
                    quote.stream_state_version,
                    quote.stream_state_root,
                ) {
                    return Err(AethelError::InvalidState);
                }
            }
            if let Some(guarantee_id) = quote.guarantee_id {
                let guarantee = self
                    .guarantees
                    .get(&id_key(&guarantee_id))
                    .ok_or(AethelError::InvalidState)?;
                if !same_request_state(
                    guarantee.request_id,
                    guarantee.series_id,
                    guarantee.stream_state_version,
                    guarantee.stream_state_root,
                    quote.request_id,
                    quote.series_id,
                    quote.stream_state_version,
                    quote.stream_state_root,
                ) {
                    return Err(AethelError::InvalidState);
                }
            }
        }
        let mut notes = BTreeSet::new();
        let mut allocation_nullifiers = BTreeSet::new();
        for (key, issuance) in &self.issuances {
            issuance.statement()?;
            if key != &id_key(&issuance.issuance_id)
                || !self.series.contains_key(&id_key(&issuance.series_id))
                || !notes.insert(issuance.note_id)
                || !allocation_nullifiers.insert(id_key(&issuance.allocation_nullifier))
            {
                return Err(AethelError::InvalidState);
            }
            let series = self
                .series
                .get(&id_key(&issuance.series_id))
                .ok_or(AethelError::InvalidState)?;
            if (series.policy.requires_credit_decision && issuance.credit_decision_id.is_none())
                || (series.policy.requires_guarantee && issuance.guarantee_id.is_none())
                || (series.policy.requires_funding_reservation
                    && issuance.funding_quote_id.is_none())
            {
                return Err(AethelError::InvalidState);
            }
            if let Some(decision_id) = issuance.credit_decision_id {
                let decision = self
                    .credit_decisions
                    .get(&id_key(&decision_id))
                    .ok_or(AethelError::InvalidState)?;
                if !same_request_state(
                    decision.request_id,
                    decision.series_id,
                    decision.stream_state_version,
                    decision.stream_state_root,
                    issuance.request_id,
                    issuance.series_id,
                    issuance.before_stream_state_version,
                    issuance.before_stream_state_root,
                ) {
                    return Err(AethelError::InvalidState);
                }
            }
            if let Some(guarantee_id) = issuance.guarantee_id {
                let guarantee = self
                    .guarantees
                    .get(&id_key(&guarantee_id))
                    .ok_or(AethelError::InvalidState)?;
                if guarantee.bound_issuance_id != Some(issuance.issuance_id)
                    || !matches!(
                        guarantee.status,
                        GuaranteeStatus::Bound | GuaranteeStatus::Claimed
                    )
                    || !same_request_state(
                        guarantee.request_id,
                        guarantee.series_id,
                        guarantee.stream_state_version,
                        guarantee.stream_state_root,
                        issuance.request_id,
                        issuance.series_id,
                        issuance.before_stream_state_version,
                        issuance.before_stream_state_root,
                    )
                    || guarantee.credit_decision_id != issuance.credit_decision_id
                {
                    return Err(AethelError::InvalidState);
                }
            }
            if let Some(quote_id) = issuance.funding_quote_id {
                let quote = self
                    .funding_quotes
                    .get(&id_key(&quote_id))
                    .ok_or(AethelError::InvalidState)?;
                if quote.bound_issuance_id != Some(issuance.issuance_id)
                    || !same_request_state(
                        quote.request_id,
                        quote.series_id,
                        quote.stream_state_version,
                        quote.stream_state_root,
                        issuance.request_id,
                        issuance.series_id,
                        issuance.before_stream_state_version,
                        issuance.before_stream_state_root,
                    )
                    || quote.credit_decision_id != issuance.credit_decision_id
                    || quote.guarantee_id != issuance.guarantee_id
                {
                    return Err(AethelError::InvalidState);
                }
            }
        }
        if allocation_nullifiers != self.used_allocation_nullifiers {
            return Err(AethelError::InvalidState);
        }
        for (key, release) in &self.guarantee_releases {
            let statement = release.statement()?;
            let provider = self.provider(&release.provider_id)?;
            provider.verify_recorded_signature(&statement, &release.signature)?;
            let guarantee = self.guarantees.get(key).ok_or(AethelError::InvalidState)?;
            if key != &id_key(&release.guarantee_id)
                || guarantee.provider_id != release.provider_id
                || guarantee.status != GuaranteeStatus::Released
                || !provider
                    .capabilities
                    .contains(&ProviderCapability::Guarantor)
            {
                return Err(AethelError::InvalidState);
            }
        }
        for (key, default) in &self.default_attestations {
            let statement = default.statement()?;
            let provider = self.provider(&default.provider_id)?;
            provider.verify_recorded_signature(&statement, &default.signature)?;
            if key != &id_key(&default.attestation_id)
                || !provider
                    .capabilities
                    .contains(&ProviderCapability::Servicer)
            {
                return Err(AethelError::InvalidState);
            }
        }
        for (key, claim) in &self.guarantee_claims {
            claim.statement()?;
            if key != &id_key(&claim.claim_id)
                || !self.guarantees.contains_key(&id_key(&claim.guarantee_id))
                || !self.issuances.contains_key(&id_key(&claim.issuance_id))
                || !self
                    .default_attestations
                    .contains_key(&id_key(&claim.default_attestation_id))
            {
                return Err(AethelError::InvalidState);
            }
            let guarantee = self
                .guarantees
                .get(&id_key(&claim.guarantee_id))
                .ok_or(AethelError::InvalidState)?;
            let issuance = self
                .issuances
                .get(&id_key(&claim.issuance_id))
                .ok_or(AethelError::InvalidState)?;
            let series = self
                .series
                .get(&id_key(&issuance.series_id))
                .ok_or(AethelError::InvalidState)?;
            let default = self
                .default_attestations
                .get(&id_key(&claim.default_attestation_id))
                .ok_or(AethelError::InvalidState)?;
            if guarantee.status != GuaranteeStatus::Claimed
                || guarantee.bound_issuance_id != Some(claim.issuance_id)
                || default.stream_id != series.stream_id
            {
                return Err(AethelError::InvalidState);
            }
        }
        if self
            .used_operations
            .iter()
            .chain(&self.used_allocation_nullifiers)
            .chain(&self.used_subject_nullifiers)
            .any(|key| !valid_hex_id(key))
            || self.used_provider_nonces.iter().any(|key| {
                key.split_once(':')
                    .is_none_or(|(provider, nonce)| !valid_hex_id(provider) || !valid_hex_id(nonce))
            })
        {
            return Err(AethelError::InvalidState);
        }
        Ok(())
    }

    /// Hands the presentation to DeKYX. Aethel contributes only the series
    /// policy, the vouching provider, and the exact artifact; every credential,
    /// key-epoch, revocation, qualification, and proof check is DeKYX's.
    fn verify_subject_presentation(
        &mut self,
        presentation: &AnonymousPresentation,
        artifact: ConfidentialArtifact<'_>,
        now: u64,
    ) -> Result<ConfidentialSubjectBinding, AethelError> {
        let series = self.series(&artifact.series_id())?.clone();
        let issuer_provider_id = presentation.credential.issuer_id;
        self.active_provider(
            &issuer_provider_id,
            ProviderCapability::CredentialIssuer,
            now,
        )?;
        let issuer = self
            .credential_issuers
            .issuer(
                &issuer_provider_id,
                presentation.credential.issuer_key_epoch,
            )
            .map_err(AethelError::Credential)?
            .clone();
        if !issuer.active_for(series.policy.subject_kind, now) {
            return Err(AethelError::Credential(DeKyxError::IssuerNotAuthorized));
        }
        if series
            .policy
            .accepted_issuer_namespace_digest
            .is_some_and(|namespace| namespace != issuer.namespace_digest)
        {
            return Err(AethelError::InvalidConfidentialSubject);
        }
        let request = artifact.eligibility_request(&series, &issuer)?;
        let binding = AethelDeKyxAdapter {
            directory: &self.credential_issuers,
        }
        .verify(&request, presentation, now)
        .map_err(AethelError::Credential)?;
        if binding.valid_until < artifact.valid_until() {
            return Err(AethelError::MismatchedConfidentialSubject);
        }
        self.consumed_presentations
            .consume(&binding.subject_nullifier, &request.context())
            .map_err(AethelError::Credential)?;
        Ok(binding)
    }

    fn bind_or_match_confidential_subject(
        &mut self,
        binding: ConfidentialSubjectBinding,
        now: u64,
    ) -> Result<(), AethelError> {
        if !binding_is_well_formed(&binding) {
            return Err(AethelError::InvalidConfidentialSubject);
        }
        if binding.valid_until < now {
            return Err(AethelError::OutsideValidityWindow);
        }
        self.active_provider(
            &binding.issuer_provider_id,
            ProviderCapability::CredentialIssuer,
            now,
        )?;
        let request_key = id_key(&binding.request_id);
        if let Some(existing) = self.confidential_subjects.get(&request_key) {
            return if existing.same_subject_line(&binding) {
                Ok(())
            } else {
                Err(AethelError::MismatchedConfidentialSubject)
            };
        }
        let nullifier_key = id_key(&binding.subject_nullifier);
        if self.used_subject_nullifiers.contains(&nullifier_key) {
            return Err(AethelError::Replay);
        }
        self.used_subject_nullifiers.insert(nullifier_key);
        self.confidential_subjects.insert(request_key, binding);
        Ok(())
    }

    fn validate_credit_subject_binding(
        &self,
        decision: &CreditDecision,
    ) -> Result<(), AethelError> {
        let series = self.series(&decision.series_id)?;
        let binding = self.confidential_subject(&decision.request_id);
        if series.policy.requires_confidential_subject && binding.is_none() {
            return Err(AethelError::MissingConfidentialSubject);
        }
        if let Some(binding) = binding {
            if binding.policy_digest != series.policy.eligibility_policy_digest
                || binding.valid_until < decision.valid_until
            {
                return Err(AethelError::MismatchedConfidentialSubject);
            }
        }
        Ok(())
    }

    fn validate_guarantee_subject_binding(
        &self,
        guarantee: &GuaranteeCommitment,
    ) -> Result<(), AethelError> {
        let series = self.series(&guarantee.series_id)?;
        let binding = self.confidential_subject(&guarantee.request_id);
        if series.policy.requires_confidential_subject && binding.is_none() {
            return Err(AethelError::MissingConfidentialSubject);
        }
        if let Some(binding) = binding {
            if binding.policy_digest != series.policy.eligibility_policy_digest
                || binding.valid_until < guarantee.valid_until
            {
                return Err(AethelError::MismatchedConfidentialSubject);
            }
        }
        Ok(())
    }

    fn series(&self, series_id: &Identifier) -> Result<&ReceivableSeries, AethelError> {
        self.series
            .get(&id_key(series_id))
            .ok_or(AethelError::UnknownSeries)
    }

    fn decision(&self, decision_id: &Identifier) -> Result<&CreditDecision, AethelError> {
        self.credit_decisions
            .get(&id_key(decision_id))
            .ok_or(AethelError::UnknownCreditDecision)
    }

    fn guarantee(&self, guarantee_id: &Identifier) -> Result<&GuaranteeCommitment, AethelError> {
        self.guarantees
            .get(&id_key(guarantee_id))
            .ok_or(AethelError::UnknownGuarantee)
    }

    fn active_provider(
        &self,
        provider_id: &Identifier,
        capability: ProviderCapability,
        now: u64,
    ) -> Result<&ProviderDefinition, AethelError> {
        let provider = self.provider(provider_id)?;
        if !provider.has(capability, now) {
            return Err(AethelError::MissingProviderCapability);
        }
        Ok(provider)
    }

    fn ensure_series_state(
        &self,
        series_id: &Identifier,
        version: u64,
        root: [u8; 32],
        now: u64,
    ) -> Result<&RegisteredStream, AethelError> {
        let series = self.series(series_id)?;
        if series.status != ReceivableStatus::Active
            || now < series.valid_from
            || now > series.maturity
        {
            return Err(AethelError::SeriesUnavailable);
        }
        let stream = self.stream(&series.stream_id)?;
        if stream.state.version != version || stream.state.root()? != root {
            return Err(AethelError::StaleStreamState);
        }
        Ok(stream)
    }

    fn validate_issuance_artifacts(
        &self,
        issuance: &ReceivableIssuance,
        series: &ReceivableSeries,
        now: u64,
    ) -> Result<(), AethelError> {
        if (series.policy.requires_credit_decision && issuance.credit_decision_id.is_none())
            || (series.policy.requires_guarantee && issuance.guarantee_id.is_none())
            || (series.policy.requires_funding_reservation && issuance.funding_quote_id.is_none())
        {
            return Err(AethelError::MissingRequiredArtifact);
        }
        if let Some(decision_id) = issuance.credit_decision_id {
            let decision = self.decision(&decision_id)?;
            if !same_request_state(
                decision.request_id,
                decision.series_id,
                decision.stream_state_version,
                decision.stream_state_root,
                issuance.request_id,
                issuance.series_id,
                issuance.before_stream_state_version,
                issuance.before_stream_state_root,
            ) || decision.valid_until < now
            {
                return Err(AethelError::MismatchedArtifact);
            }
        }
        if let Some(guarantee_id) = issuance.guarantee_id {
            let guarantee = self.guarantee(&guarantee_id)?;
            if !same_request_state(
                guarantee.request_id,
                guarantee.series_id,
                guarantee.stream_state_version,
                guarantee.stream_state_root,
                issuance.request_id,
                issuance.series_id,
                issuance.before_stream_state_version,
                issuance.before_stream_state_root,
            ) || guarantee.status != GuaranteeStatus::Available
                || guarantee.valid_until < now
                || guarantee.credit_decision_id != issuance.credit_decision_id
            {
                return Err(AethelError::MismatchedArtifact);
            }
        }
        if let Some(quote_id) = issuance.funding_quote_id {
            let quote = self
                .funding_quotes
                .get(&id_key(&quote_id))
                .ok_or(AethelError::UnknownFundingQuote)?;
            if !same_request_state(
                quote.request_id,
                quote.series_id,
                quote.stream_state_version,
                quote.stream_state_root,
                issuance.request_id,
                issuance.series_id,
                issuance.before_stream_state_version,
                issuance.before_stream_state_root,
            ) || quote.bound_issuance_id.is_some()
                || quote.valid_until < now
                || quote.credit_decision_id != issuance.credit_decision_id
                || quote.guarantee_id != issuance.guarantee_id
            {
                return Err(AethelError::MismatchedArtifact);
            }
        }
        Ok(())
    }

    fn ensure_artifact_ids_unused<T>(
        &self,
        operation_id: &Identifier,
        provider_id: &Identifier,
        nonce: &Identifier,
        artifact_id: &Identifier,
        artifacts: &BTreeMap<String, T>,
    ) -> Result<(), AethelError> {
        self.ensure_operation_unused(operation_id)?;
        if artifacts.contains_key(&id_key(artifact_id))
            || self
                .used_provider_nonces
                .contains(&provider_nonce_key(provider_id, nonce))
        {
            return Err(AethelError::Replay);
        }
        Ok(())
    }

    fn ensure_operation_unused(&self, operation_id: &Identifier) -> Result<(), AethelError> {
        if *operation_id == ZERO || self.used_operations.contains(&id_key(operation_id)) {
            return Err(AethelError::Replay);
        }
        Ok(())
    }

    fn consume_operation(&mut self, operation_id: &Identifier) -> Result<(), AethelError> {
        self.ensure_operation_unused(operation_id)?;
        self.used_operations.insert(id_key(operation_id));
        Ok(())
    }

    fn consume_provider_artifact(
        &mut self,
        operation_id: &Identifier,
        provider_id: &Identifier,
        nonce: &Identifier,
    ) -> Result<(), AethelError> {
        let nonce_key = provider_nonce_key(provider_id, nonce);
        if self.used_provider_nonces.contains(&nonce_key) {
            return Err(AethelError::Replay);
        }
        self.consume_operation(operation_id)?;
        self.used_provider_nonces.insert(nonce_key);
        Ok(())
    }
}

fn provider_nonce_key(provider_id: &Identifier, nonce: &Identifier) -> String {
    format!("{}:{}", id_key(provider_id), id_key(nonce))
}

fn valid_hex_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[allow(clippy::too_many_arguments)]
fn same_request_state(
    left_request: Identifier,
    left_series: Identifier,
    left_version: u64,
    left_root: [u8; 32],
    right_request: Identifier,
    right_series: Identifier,
    right_version: u64,
    right_root: [u8; 32],
) -> bool {
    left_request == right_request
        && left_series == right_series
        && left_version == right_version
        && left_root == right_root
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AethelError {
    #[error("Aethel state encoding failed")]
    Encoding,
    #[error("Aethel state is invalid")]
    InvalidState,
    #[error("provider definition is invalid")]
    InvalidProvider,
    #[error("provider key is invalid")]
    InvalidProviderKey,
    #[error("provider signature is invalid")]
    InvalidSignature,
    #[error("guarantee-capable provider has no DeFMI guarantee authority")]
    MissingGuaranteeAuthority,
    #[error("provider is unknown")]
    UnknownProvider,
    #[error("provider is already registered")]
    DuplicateProvider,
    #[error("provider lacks the required active capability")]
    MissingProviderCapability,
    #[error("provider is revoked")]
    ProviderRevoked,
    #[error("provider control sequence is stale")]
    StaleSequence,
    #[error("artifact is outside its validity window")]
    OutsideValidityWindow,
    #[error("stream state is invalid")]
    InvalidStream,
    #[error("stream is unknown")]
    UnknownStream,
    #[error("stream is already registered")]
    DuplicateStream,
    #[error("stream transition is invalid")]
    InvalidStreamTransition,
    #[error("stream is not eligible for a new receivable")]
    StreamUnavailable,
    #[error("stream state is stale")]
    StaleStreamState,
    #[error("receivable series is invalid")]
    InvalidSeries,
    #[error("receivable series is unknown")]
    UnknownSeries,
    #[error("receivable series already exists")]
    DuplicateSeries,
    #[error("receivable series is unavailable")]
    SeriesUnavailable,
    #[error("credit decision is invalid")]
    InvalidCreditDecision,
    #[error("confidential credit or guarantee subject binding is invalid")]
    InvalidConfidentialSubject,
    #[error("confidential subject proof is required by the receivable series")]
    MissingConfidentialSubject,
    #[error("confidential subject binding does not match the provider artifact")]
    MismatchedConfidentialSubject,
    #[error("credential issuer registration is invalid")]
    InvalidCredentialIssuer,
    #[error("credential status publication is invalid")]
    InvalidCredentialStatus,
    #[error("DeKYX rejected the subject evidence: {0}")]
    Credential(DeKyxError),
    #[error("credit decision is unknown")]
    UnknownCreditDecision,
    #[error("guarantee commitment is invalid")]
    InvalidGuarantee,
    #[error("guarantee commitment is unknown")]
    UnknownGuarantee,
    #[error("guarantee commitment is unavailable")]
    GuaranteeUnavailable,
    #[error("guarantee release is invalid")]
    InvalidGuaranteeRelease,
    #[error("funding quote is invalid")]
    InvalidFundingQuote,
    #[error("funding quote is unknown")]
    UnknownFundingQuote,
    #[error("receivable issuance is invalid")]
    InvalidIssuance,
    #[error("receivable issuance or allocation was already used")]
    DuplicateIssuance,
    #[error("receivable issuance is unknown")]
    UnknownIssuance,
    #[error("required credit, guarantee, or funding artifact is missing")]
    MissingRequiredArtifact,
    #[error("provider artifacts do not describe the same request and stream state")]
    MismatchedArtifact,
    #[error("default attestation is invalid")]
    InvalidDefaultAttestation,
    #[error("default attestation is unknown")]
    UnknownDefaultAttestation,
    #[error("guarantee claim is invalid")]
    InvalidGuaranteeClaim,
    #[error("operation, nonce, or nullifier was already used")]
    Replay,
    #[error("arithmetic overflow")]
    ArithmeticOverflow,
}

impl From<ProviderError> for AethelError {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::Encoding => Self::Encoding,
            ProviderError::InvalidProvider => Self::InvalidProvider,
            ProviderError::InvalidProviderKey => Self::InvalidProviderKey,
            ProviderError::InvalidSignature => Self::InvalidSignature,
            ProviderError::MissingGuaranteeAuthority => Self::MissingGuaranteeAuthority,
            ProviderError::UnknownProvider => Self::UnknownProvider,
            ProviderError::MissingProviderCapability => Self::MissingProviderCapability,
            ProviderError::InvalidStream => Self::InvalidStream,
            ProviderError::InvalidStreamTransition => Self::InvalidStreamTransition,
            ProviderError::StreamUnavailable => Self::StreamUnavailable,
            ProviderError::InvalidCreditDecision => Self::InvalidCreditDecision,
            ProviderError::InvalidGuarantee => Self::InvalidGuarantee,
            ProviderError::InvalidGuaranteeRelease => Self::InvalidGuaranteeRelease,
            ProviderError::InvalidFundingQuote => Self::InvalidFundingQuote,
            ProviderError::InvalidDefaultAttestation => Self::InvalidDefaultAttestation,
            ProviderError::InvalidCredentialIssuer => Self::InvalidCredentialIssuer,
            ProviderError::InvalidCredentialStatus => Self::InvalidCredentialStatus,
            ProviderError::Credential(error) => Self::Credential(error),
            ProviderError::ArithmeticOverflow => Self::ArithmeticOverflow,
        }
    }
}

/// The book is the authoritative provider registry of its deployment, so any
/// verifier built on the provider SDK (a servicing book, a host adapter) can
/// check artifacts against exactly the providers Aethel has admitted.
impl ProviderRegistry for AethelBook {
    fn provider(&self, provider_id: &Identifier) -> Option<&ProviderDefinition> {
        self.providers.get(&id_key(provider_id))
    }
}
