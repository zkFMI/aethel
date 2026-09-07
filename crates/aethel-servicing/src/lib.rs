//! Servicing: the independent record of whether a stream is paying.
//!
//! A servicer or stream attestor submits signed [`PaymentEvidence`] against
//! the installments of a stream. The [`ServicingBook`] derives the servicing
//! status (performing, delinquent, cured, defaulted) from that evidence and
//! the stream's grace and cure terms alone. Observed payment is a different
//! thing from a credit provider's opinion: a credit decision is not evidence,
//! and a provider registered only as a credit assessor, guarantor, liquidity
//! provider, or credential issuer cannot submit evidence.
//!
//! Default is evidence-driven. The book produces [`DefaultEvidence`] only when
//! the missed installments and elapsed cure window meet the terms, and it
//! accepts a `DefaultAttestation` only from a registered servicer and only
//! when the attestation names exactly that evidence. An issuer, a creditor, or
//! a tokenization module cannot declare a default the evidence does not
//! support, and cannot sign one at all unless it is a registered servicer.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use aethel_provider_sdk::{
    DefaultAttestation, ProviderCapability, ProviderError, ProviderRegistry, SignedArtifact,
};
use aethel_types::{
    digest, id_key, valid_time, Commitment, EncodingError, Identifier, MAX_UNIX_TIME, ZERO,
};

const PAYMENT_EVIDENCE_DOMAIN: &[u8] = b"AETHEL:PAYMENT-EVIDENCE:v1";
const DEFAULT_EVENT_DOMAIN: &[u8] = b"AETHEL:DEFAULT-EVENT:v1";
const DEFAULT_REASON_DOMAIN: &[u8] = b"AETHEL:DEFAULT-REASON:v1";
const SERVICING_BOOK_DOMAIN: &[u8] = b"AETHEL:SERVICING-BOOK:v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DueInstallment {
    pub sequence: u64,
    pub due_at: u64,
    pub units: u64,
}

/// The contractual terms servicing evaluates against.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServicingTerms {
    pub stream_id: Identifier,
    pub schedule: Vec<DueInstallment>,
    /// Seconds after `due_at` before an unpaid installment counts as missed.
    pub grace_seconds: u64,
    /// Seconds after the first missed installment's grace end during which
    /// payment cures the delinquency without a default.
    pub cure_window_seconds: u64,
    /// Missed installments (at once) required before default is supported.
    pub default_after_missed: u32,
}

impl ServicingTerms {
    pub fn validate(&self) -> Result<(), ServicingError> {
        if self.stream_id == ZERO
            || self.schedule.is_empty()
            || self.default_after_missed == 0
            || self.grace_seconds > MAX_UNIX_TIME
            || self.cure_window_seconds > MAX_UNIX_TIME
        {
            return Err(ServicingError::InvalidTerms);
        }
        let mut previous: Option<&DueInstallment> = None;
        for installment in &self.schedule {
            if installment.sequence != previous.map_or(1, |last| last.sequence + 1)
                || installment.units == 0
                || !valid_time(installment.due_at)
                || previous.is_some_and(|last| last.due_at >= installment.due_at)
            {
                return Err(ServicingError::InvalidTerms);
            }
            previous = Some(installment);
        }
        Ok(())
    }

    pub fn installment(&self, sequence: u64) -> Option<&DueInstallment> {
        self.schedule
            .iter()
            .find(|installment| installment.sequence == sequence)
    }
}

/// A signed observation that units were paid against one installment. The
/// signer is a servicer or the stream's attestor; `source_evidence_digest`
/// names the settlement receipt or source record the observation rests on.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaymentEvidence {
    pub evidence_id: Identifier,
    pub operation_id: Identifier,
    pub provider_id: Identifier,
    pub stream_id: Identifier,
    pub installment_sequence: u64,
    pub paid_units: u64,
    pub observed_at: u64,
    pub source_evidence_digest: Commitment,
    pub signature: Vec<u8>,
}

impl PaymentEvidence {
    pub fn statement(&self) -> Result<Commitment, ServicingError> {
        if [
            self.evidence_id,
            self.operation_id,
            self.provider_id,
            self.stream_id,
            self.source_evidence_digest,
        ]
        .contains(&ZERO)
            || self.installment_sequence == 0
            || self.paid_units == 0
            || !valid_time(self.observed_at)
        {
            return Err(ServicingError::InvalidEvidence);
        }
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        Ok(digest(PAYMENT_EVIDENCE_DOMAIN, &unsigned)?)
    }
}

/// Payment evidence is signed under the servicer capability; a stream
/// attestor's evidence is accepted through the explicit second check in
/// [`ServicingBook::record_payment_evidence`].
impl SignedArtifact for PaymentEvidence {
    fn capability(&self) -> ProviderCapability {
        ProviderCapability::Servicer
    }

    fn provider_id(&self) -> Identifier {
        self.provider_id
    }

    fn statement(&self) -> Result<Commitment, ProviderError> {
        PaymentEvidence::statement(self).map_err(|_| ProviderError::InvalidDefaultAttestation)
    }

    fn signature(&self) -> &[u8] {
        &self.signature
    }

    fn set_signature(&mut self, signature: Vec<u8>) {
        self.signature = signature;
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum ServicingStatus {
    Performing,
    Delinquent { since: u64, missed: Vec<u64> },
    Cured { at: u64 },
    Defaulted { attestation_id: Identifier },
}

/// The evidence a default rests on. Its `event_digest` is what a
/// `DefaultAttestation` must carry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DefaultEvidence {
    pub stream_id: Identifier,
    pub missed_sequences: Vec<u64>,
    pub first_missed_due_at: u64,
    pub evaluated_at: u64,
    pub evidence_root: Commitment,
    pub event_digest: Commitment,
    pub reason_digest: Commitment,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServicingBook {
    pub terms: ServicingTerms,
    pub evidence: BTreeMap<String, PaymentEvidence>,
    pub status: ServicingStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_evidence: Option<DefaultEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_attestation: Option<DefaultAttestation>,
    pub used_operations: BTreeSet<String>,
}

impl ServicingBook {
    pub fn new(terms: ServicingTerms) -> Result<Self, ServicingError> {
        terms.validate()?;
        Ok(Self {
            terms,
            evidence: BTreeMap::new(),
            status: ServicingStatus::Performing,
            default_evidence: None,
            accepted_attestation: None,
            used_operations: BTreeSet::new(),
        })
    }

    pub fn root(&self) -> Result<Commitment, ServicingError> {
        self.validate()?;
        Ok(digest(SERVICING_BOOK_DOMAIN, self)?)
    }

    /// Units observed paid against one installment.
    pub fn paid_units(&self, sequence: u64) -> u64 {
        self.evidence
            .values()
            .filter(|evidence| evidence.installment_sequence == sequence)
            .map(|evidence| evidence.paid_units)
            .sum()
    }

    /// Installments whose grace period has ended at `now` without full payment.
    pub fn missed(&self, now: u64) -> Vec<&DueInstallment> {
        self.terms
            .schedule
            .iter()
            .filter(|installment| {
                installment.due_at.saturating_add(self.terms.grace_seconds) < now
                    && self.paid_units(installment.sequence) < installment.units
            })
            .collect()
    }

    /// Records an observation. The signer must be a registered servicer or
    /// stream attestor active at `now`; a provider registered under any other
    /// capability is not an observer of payment.
    pub fn record_payment_evidence<R: ProviderRegistry>(
        &mut self,
        evidence: PaymentEvidence,
        registry: &R,
        now: u64,
    ) -> Result<Commitment, ServicingError> {
        if matches!(self.status, ServicingStatus::Defaulted { .. }) {
            return Err(ServicingError::AlreadyDefaulted);
        }
        let statement = evidence.statement()?;
        let provider = registry
            .provider(&evidence.provider_id)
            .ok_or(ProviderError::UnknownProvider)?;
        if !provider.has(ProviderCapability::Servicer, now)
            && !provider.has(ProviderCapability::StreamAttestor, now)
        {
            return Err(ServicingError::NotAnObserver);
        }
        provider.verify_new_signature(&statement, &evidence.signature, now)?;
        if evidence.stream_id != self.terms.stream_id || evidence.observed_at > now {
            return Err(ServicingError::InvalidEvidence);
        }
        self.terms
            .installment(evidence.installment_sequence)
            .ok_or(ServicingError::UnknownInstallment)?;
        let key = id_key(&evidence.evidence_id);
        if self.evidence.contains_key(&key) {
            return Err(ServicingError::Replay);
        }
        self.consume_operation(&evidence.operation_id)?;
        self.evidence.insert(key, evidence);
        self.evaluate(now);
        Ok(statement)
    }

    /// Re-derives the status from the evidence at `now`. A default, once
    /// attested, is terminal.
    pub fn evaluate(&mut self, now: u64) -> &ServicingStatus {
        if matches!(self.status, ServicingStatus::Defaulted { .. }) {
            return &self.status;
        }
        let missed = self.missed(now);
        self.status = if missed.is_empty() {
            match self.status {
                ServicingStatus::Delinquent { .. } => ServicingStatus::Cured { at: now },
                ServicingStatus::Cured { at } => ServicingStatus::Cured { at },
                _ => ServicingStatus::Performing,
            }
        } else {
            let since = missed[0].due_at.saturating_add(self.terms.grace_seconds);
            ServicingStatus::Delinquent {
                since,
                missed: missed
                    .iter()
                    .map(|installment| installment.sequence)
                    .collect(),
            }
        };
        &self.status
    }

    /// Produces the evidence a default may rest on, or refuses when the terms
    /// are not met: too few installments missed, or the cure window still open.
    pub fn default_evidence(&mut self, now: u64) -> Result<DefaultEvidence, ServicingError> {
        if let Some(existing) = &self.default_evidence {
            return Ok(existing.clone());
        }
        self.evaluate(now);
        let ServicingStatus::Delinquent { since, missed } = &self.status else {
            return Err(ServicingError::DefaultUnsupported);
        };
        if missed.len() < self.terms.default_after_missed as usize
            || now < since.saturating_add(self.terms.cure_window_seconds)
        {
            return Err(ServicingError::DefaultUnsupported);
        }
        let first = self
            .terms
            .installment(missed[0])
            .expect("missed installments come from the schedule");
        let evidence_root = digest(
            PAYMENT_EVIDENCE_DOMAIN,
            &self.evidence.keys().collect::<Vec<_>>(),
        )?;
        let event_digest = digest(
            DEFAULT_EVENT_DOMAIN,
            &(
                self.terms.stream_id,
                missed,
                first.due_at,
                now,
                evidence_root,
            ),
        )?;
        let reason_digest = digest(
            DEFAULT_REASON_DOMAIN,
            &(
                "missed installments beyond grace and cure window",
                missed.len() as u64,
                self.terms.grace_seconds,
                self.terms.cure_window_seconds,
            ),
        )?;
        let evidence = DefaultEvidence {
            stream_id: self.terms.stream_id,
            missed_sequences: missed.clone(),
            first_missed_due_at: first.due_at,
            evaluated_at: now,
            evidence_root,
            event_digest,
            reason_digest,
        };
        self.default_evidence = Some(evidence.clone());
        Ok(evidence)
    }

    /// The unsigned attestation a servicer signs for the stored evidence. The
    /// stream state version and root are those of the Aethel stream after its
    /// attestor moved it to `Defaulted`; the servicer supplies them.
    pub fn draft_default_attestation(
        &self,
        operation_id: Identifier,
        attestation_id: Identifier,
        servicer_provider_id: Identifier,
        stream_state_version: u64,
        stream_state_root: Commitment,
        observed_at: u64,
    ) -> Result<DefaultAttestation, ServicingError> {
        let evidence = self
            .default_evidence
            .as_ref()
            .ok_or(ServicingError::DefaultUnsupported)?;
        Ok(DefaultAttestation {
            operation_id,
            attestation_id,
            provider_id: servicer_provider_id,
            stream_id: evidence.stream_id,
            stream_state_version,
            stream_state_root,
            event_digest: evidence.event_digest,
            reason_digest: evidence.reason_digest,
            observed_at,
            signature: Vec::new(),
        })
    }

    /// Accepts a signed default attestation. Its signer must be a registered
    /// servicer, and its event and reason digests must be the ones this book
    /// derived from payment evidence; anything else is a self-declared
    /// default and is refused.
    pub fn accept_default_attestation<R: ProviderRegistry>(
        &mut self,
        attestation: DefaultAttestation,
        registry: &R,
        now: u64,
    ) -> Result<Commitment, ServicingError> {
        if matches!(self.status, ServicingStatus::Defaulted { .. }) {
            return Err(ServicingError::AlreadyDefaulted);
        }
        let statement =
            registry
                .verify_artifact(&attestation, now)
                .map_err(|error| match error {
                    ProviderError::MissingProviderCapability | ProviderError::UnknownProvider => {
                        ServicingError::NotAServicer
                    }
                    other => ServicingError::Provider(other),
                })?;
        let evidence = self
            .default_evidence
            .as_ref()
            .ok_or(ServicingError::UnsupportedDefault)?;
        if attestation.stream_id != evidence.stream_id
            || attestation.event_digest != evidence.event_digest
            || attestation.reason_digest != evidence.reason_digest
            || attestation.observed_at < evidence.evaluated_at
            || attestation.observed_at > now
        {
            return Err(ServicingError::UnsupportedDefault);
        }
        self.consume_operation(&attestation.operation_id)?;
        self.status = ServicingStatus::Defaulted {
            attestation_id: attestation.attestation_id,
        };
        self.accepted_attestation = Some(attestation);
        Ok(statement)
    }

    pub fn validate(&self) -> Result<(), ServicingError> {
        self.terms.validate()?;
        for (key, evidence) in &self.evidence {
            evidence.statement()?;
            if key != &id_key(&evidence.evidence_id)
                || evidence.stream_id != self.terms.stream_id
                || self
                    .terms
                    .installment(evidence.installment_sequence)
                    .is_none()
                || !self
                    .used_operations
                    .contains(&id_key(&evidence.operation_id))
            {
                return Err(ServicingError::InvalidState);
            }
        }
        match (
            &self.status,
            &self.default_evidence,
            &self.accepted_attestation,
        ) {
            (ServicingStatus::Defaulted { attestation_id }, Some(evidence), Some(attestation)) => {
                attestation.statement()?;
                if attestation.attestation_id != *attestation_id
                    || attestation.event_digest != evidence.event_digest
                    || attestation.reason_digest != evidence.reason_digest
                    || evidence.stream_id != self.terms.stream_id
                    || !self
                        .used_operations
                        .contains(&id_key(&attestation.operation_id))
                {
                    return Err(ServicingError::InvalidState);
                }
            }
            (ServicingStatus::Defaulted { .. }, _, _) | (_, _, Some(_)) => {
                return Err(ServicingError::InvalidState)
            }
            _ => {}
        }
        Ok(())
    }

    fn consume_operation(&mut self, operation_id: &Identifier) -> Result<(), ServicingError> {
        let key = id_key(operation_id);
        if *operation_id == ZERO || self.used_operations.contains(&key) {
            return Err(ServicingError::Replay);
        }
        self.used_operations.insert(key);
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ServicingError {
    #[error("servicing record encoding failed")]
    Encoding,
    #[error("servicing state is invalid")]
    InvalidState,
    #[error("servicing terms are invalid")]
    InvalidTerms,
    #[error("payment evidence is invalid")]
    InvalidEvidence,
    #[error("installment is not in the servicing schedule")]
    UnknownInstallment,
    #[error("signer is not a registered servicer or stream attestor; it does not observe payment")]
    NotAnObserver,
    #[error("default attestation signer is not a registered servicer")]
    NotAServicer,
    #[error("payment evidence does not support a default")]
    DefaultUnsupported,
    #[error("default attestation does not name the evidence this book derived")]
    UnsupportedDefault,
    #[error("stream is already in attested default")]
    AlreadyDefaulted,
    #[error("provider contract rejected the artifact: {0}")]
    Provider(ProviderError),
    #[error("operation or evidence was already recorded")]
    Replay,
}

impl From<EncodingError> for ServicingError {
    fn from(_: EncodingError) -> Self {
        Self::Encoding
    }
}

impl From<ProviderError> for ServicingError {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use aethel_provider_sdk::{ProviderDefinition, ProviderStatus};
    use ed25519_dalek::SigningKey;

    use super::*;

    fn sign_artifact<A: aethel_provider_sdk::SignedArtifact>(
        artifact: &mut A,
        key: &SigningKey,
    ) -> Result<[u8; 32], aethel_provider_sdk::ProviderError> {
        let participant = [artifact.provider_id()[0] + 40; 32];
        aethel_provider_sdk::sign_artifact(
            artifact,
            &aethel_provider_sdk::test_support::signer(key),
            &aethel_provider_sdk::test_support::key_record(key, participant, 1),
        )
    }

    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn provider(
        byte: u8,
        key: &SigningKey,
        capabilities: &[ProviderCapability],
    ) -> ProviderDefinition {
        ProviderDefinition {
            provider_id: id(byte),
            participant_id: id(byte + 40),
            capabilities: capabilities.iter().copied().collect::<BTreeSet<_>>(),
            public_key: key.verifying_key().to_bytes(),
            artifact_key: aethel_provider_sdk::test_support::key_record(key, id(byte + 40), 1),
            policy_registry_digest: id(byte + 80),
            defmi_guarantor_id: None,
            valid_from: 1,
            valid_until: 100_000,
            sequence: 0,
            status: ProviderStatus::Active,
            retired_keys: Vec::new(),
        }
    }

    fn registry() -> BTreeMap<String, ProviderDefinition> {
        [
            provider(
                1,
                &SigningKey::from_bytes(&id(101)),
                &[ProviderCapability::StreamAttestor],
            ),
            provider(
                2,
                &SigningKey::from_bytes(&id(102)),
                &[ProviderCapability::CreditAssessor],
            ),
            provider(
                5,
                &SigningKey::from_bytes(&id(105)),
                &[ProviderCapability::Servicer],
            ),
        ]
        .into_iter()
        .map(|provider| (id_key(&provider.provider_id), provider))
        .collect()
    }

    fn terms() -> ServicingTerms {
        ServicingTerms {
            stream_id: id(20),
            schedule: (1..=4)
                .map(|sequence| DueInstallment {
                    sequence,
                    due_at: sequence * 100,
                    units: 40,
                })
                .collect(),
            grace_seconds: 10,
            cure_window_seconds: 50,
            default_after_missed: 2,
        }
    }

    fn evidence(provider: u8, key_seed: u8, sequence: u64, units: u64, at: u64) -> PaymentEvidence {
        let mut evidence = PaymentEvidence {
            evidence_id: id(150 + sequence as u8 + provider),
            operation_id: id(170 + sequence as u8 + provider),
            provider_id: id(provider),
            stream_id: id(20),
            installment_sequence: sequence,
            paid_units: units,
            observed_at: at,
            source_evidence_digest: id(9),
            signature: Vec::new(),
        };
        sign_artifact(&mut evidence, &SigningKey::from_bytes(&id(key_seed))).unwrap();
        evidence
    }

    #[test]
    fn only_a_servicer_or_attestor_observes_payment() {
        let registry = registry();
        let mut book = ServicingBook::new(terms()).unwrap();
        book.record_payment_evidence(evidence(1, 101, 1, 40, 95), &registry, 96)
            .unwrap();
        book.record_payment_evidence(evidence(5, 105, 2, 40, 195), &registry, 196)
            .unwrap();
        assert_eq!(
            book.record_payment_evidence(evidence(2, 102, 3, 40, 295), &registry, 296),
            Err(ServicingError::NotAnObserver)
        );
        assert_eq!(
            book.record_payment_evidence(evidence(5, 101, 3, 40, 295), &registry, 296),
            Err(ServicingError::Provider(ProviderError::InvalidSignature))
        );
        assert_eq!(book.paid_units(1), 40);
        assert_eq!(book.evaluate(300), &ServicingStatus::Performing);
        assert!(book.validate().is_ok());
    }

    #[test]
    fn delinquency_follows_the_grace_period_and_cures_on_payment() {
        let registry = registry();
        let mut book = ServicingBook::new(terms()).unwrap();
        assert_eq!(book.evaluate(110), &ServicingStatus::Performing);
        assert_eq!(
            book.evaluate(111),
            &ServicingStatus::Delinquent {
                since: 110,
                missed: vec![1]
            }
        );
        assert_eq!(
            book.default_evidence(200),
            Err(ServicingError::DefaultUnsupported)
        );
        book.record_payment_evidence(evidence(5, 105, 1, 40, 120), &registry, 121)
            .unwrap();
        assert_eq!(book.status, ServicingStatus::Cured { at: 121 });
        assert!(book.default_evidence.is_none());
    }

    #[test]
    fn default_needs_enough_missed_installments_and_an_elapsed_cure_window() {
        let mut book = ServicingBook::new(terms()).unwrap();
        // One missed installment, cure window elapsed: not enough missed.
        assert_eq!(
            book.default_evidence(190),
            Err(ServicingError::DefaultUnsupported)
        );
        // Two missed, but the cure window (110 + 50 = 160) has passed only
        // for the first; the second was missed at 210. Default is supported
        // at 211 because the window is measured from the first miss.
        assert_eq!(
            book.default_evidence(210),
            Err(ServicingError::DefaultUnsupported)
        );
        let evidence = book.default_evidence(211).unwrap();
        assert_eq!(evidence.missed_sequences, vec![1, 2]);
        assert_eq!(evidence.first_missed_due_at, 100);
        assert_eq!(book.default_evidence(500).unwrap(), evidence);
    }

    #[test]
    fn a_default_attestation_is_accepted_only_from_a_servicer_and_only_for_the_evidence() {
        let registry = registry();
        let mut book = ServicingBook::new(terms()).unwrap();
        book.default_evidence(211).unwrap();
        let draft = |book: &ServicingBook, provider: u8| {
            book.draft_default_attestation(id(60), id(61), id(provider), 3, id(62), 212)
                .unwrap()
        };

        // The credit assessor (a creditor) signs the very same evidence.
        let mut creditor = draft(&book, 2);
        sign_artifact(&mut creditor, &SigningKey::from_bytes(&id(102))).unwrap();
        assert_eq!(
            book.accept_default_attestation(creditor, &registry, 213),
            Err(ServicingError::NotAServicer)
        );
        // An unregistered key (an issuer or tokenization module) signs it.
        let mut stranger = draft(&book, 9);
        sign_artifact(&mut stranger, &SigningKey::from_bytes(&id(109))).unwrap();
        assert_eq!(
            book.accept_default_attestation(stranger, &registry, 213),
            Err(ServicingError::NotAServicer)
        );
        // The servicer declares a default the evidence does not describe.
        let mut invented = draft(&book, 5);
        invented.event_digest = id(77);
        sign_artifact(&mut invented, &SigningKey::from_bytes(&id(105))).unwrap();
        assert_eq!(
            book.accept_default_attestation(invented, &registry, 213),
            Err(ServicingError::UnsupportedDefault)
        );
        // The servicer attests exactly the derived evidence.
        let mut genuine = draft(&book, 5);
        sign_artifact(&mut genuine, &SigningKey::from_bytes(&id(105))).unwrap();
        book.accept_default_attestation(genuine, &registry, 213)
            .unwrap();
        assert_eq!(
            book.status,
            ServicingStatus::Defaulted {
                attestation_id: id(61)
            }
        );
        assert!(book.validate().is_ok());
        assert!(book.root().is_ok());
        assert_eq!(
            book.record_payment_evidence(evidence(5, 105, 3, 40, 300), &registry, 301),
            Err(ServicingError::AlreadyDefaulted)
        );
    }

    #[test]
    fn a_servicer_cannot_attest_before_the_book_derived_any_evidence() {
        let registry = registry();
        let mut book = ServicingBook::new(terms()).unwrap();
        let mut early = DefaultAttestation {
            operation_id: id(60),
            attestation_id: id(61),
            provider_id: id(5),
            stream_id: id(20),
            stream_state_version: 3,
            stream_state_root: id(62),
            event_digest: id(63),
            reason_digest: id(64),
            observed_at: 150,
            signature: Vec::new(),
        };
        sign_artifact(&mut early, &SigningKey::from_bytes(&id(105))).unwrap();
        assert_eq!(
            book.accept_default_attestation(early, &registry, 151),
            Err(ServicingError::UnsupportedDefault)
        );
        assert_eq!(book.status, ServicingStatus::Performing);
    }
}
