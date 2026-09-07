//! The obligor's side of an Aethel stream.
//!
//! An obligation wallet knows the payment schedule it owes, the bounded
//! pre-authorizations under which payments may be signed, and the state of
//! every payment it has sent: pending, in flight, retrying, acknowledged, or
//! abandoned. It produces [`SigningRequest`]s for the obligor's signer, keeps a
//! durable outbound queue with at-least-once delivery and idempotent
//! acknowledgement, and reconciles against receipts from the authoritative
//! Aethel/DeFMI side.
//!
//! The wallet is not a ledger. The only paid amount it reports is the sum of
//! receipts it has reconciled; a queued or in-flight payment counts for
//! nothing until the authoritative side says it settled.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zkfmi_crypto::{
    hybrid::signature::HybridVerifier,
    key::{KeyId, KeyPurpose, KeyRecord},
    suite::{Suite, SuiteId},
    traits::{Signer, Verifier},
};

use aethel_types::{
    digest, id_key, valid_time, valid_window, Commitment, EncodingError, Identifier, ZERO,
};

const PAYMENT_DOMAIN: &[u8] = b"AETHEL:OBLIGOR-PAYMENT:v1";
const WALLET_DOMAIN: &[u8] = b"AETHEL:OBLIGATION-WALLET:v1";
const PAYMENT_SUITE: Suite = Suite::new(SuiteId::Ed25519MlDsa65);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Installment {
    pub sequence: u64,
    pub due_at: u64,
    pub units: u64,
}

/// The schedule the obligor owes on one stream, in settlement-asset units.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaymentSchedule {
    pub stream_id: Identifier,
    pub obligor_commitment: Commitment,
    pub payee_commitment: Commitment,
    pub settlement_asset_id: Identifier,
    pub installments: Vec<Installment>,
}

impl PaymentSchedule {
    pub fn validate(&self) -> Result<(), WalletError> {
        if [
            self.stream_id,
            self.obligor_commitment,
            self.payee_commitment,
            self.settlement_asset_id,
        ]
        .contains(&ZERO)
            || self.obligor_commitment == self.payee_commitment
            || self.installments.is_empty()
        {
            return Err(WalletError::InvalidSchedule);
        }
        let mut previous: Option<&Installment> = None;
        for installment in &self.installments {
            let expected_sequence = previous.map_or(1, |last| last.sequence + 1);
            if installment.sequence != expected_sequence
                || installment.units == 0
                || !valid_time(installment.due_at)
                || previous.is_some_and(|last| last.due_at >= installment.due_at)
            {
                return Err(WalletError::InvalidSchedule);
            }
            previous = Some(installment);
        }
        Ok(())
    }

    pub fn installment(&self, sequence: u64) -> Option<&Installment> {
        self.installments
            .iter()
            .find(|installment| installment.sequence == sequence)
    }

    /// Installments due in `[from, until]`.
    pub fn projection(&self, from: u64, until: u64) -> Vec<Installment> {
        self.installments
            .iter()
            .filter(|installment| from <= installment.due_at && installment.due_at <= until)
            .copied()
            .collect()
    }

    pub fn total_units(&self) -> Result<u64, WalletError> {
        self.installments
            .iter()
            .try_fold(0u64, |total, installment| {
                total.checked_add(installment.units)
            })
            .ok_or(WalletError::ArithmeticOverflow)
    }
}

/// A standing, bounded permission to sign payments to one payee. Nothing can
/// be signed above the per-payment ceiling or above the period ceiling
/// counted over all payments enqueued in one period.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreAuthorization {
    pub authorization_id: Identifier,
    pub stream_id: Identifier,
    pub obligor_commitment: Commitment,
    pub payee_commitment: Commitment,
    pub settlement_asset_id: Identifier,
    pub payment_key: KeyRecord,
    pub per_payment_ceiling: u64,
    pub period_ceiling: u64,
    pub period_seconds: u64,
    pub valid_from: u64,
    pub valid_until: u64,
}

impl PreAuthorization {
    pub fn validate(&self) -> Result<(), WalletError> {
        if [
            self.authorization_id,
            self.stream_id,
            self.obligor_commitment,
            self.payee_commitment,
            self.settlement_asset_id,
        ]
        .contains(&ZERO)
            || self.per_payment_ceiling == 0
            || self.period_ceiling < self.per_payment_ceiling
            || self.period_seconds == 0
            || !valid_window(self.valid_from, self.valid_until)
        {
            return Err(WalletError::InvalidAuthorization);
        }
        self.payment_key
            .validate()
            .map_err(|_| WalletError::InvalidAuthorization)?;
        if self.payment_key.suite != PAYMENT_SUITE
            || self.payment_key.purpose != KeyPurpose::SettlementInstruction
            || self.payment_key.participant_id.as_str() != id_key(&self.obligor_commitment)
        {
            return Err(WalletError::InvalidAuthorization);
        }
        Ok(())
    }

    fn permits(&self, payment: &PaymentRequest, now: u64) -> Result<(), WalletError> {
        if payment.authorization_id != self.authorization_id
            || payment.stream_id != self.stream_id
            || payment.obligor_commitment != self.obligor_commitment
            || payment.payee_commitment != self.payee_commitment
            || payment.settlement_asset_id != self.settlement_asset_id
        {
            return Err(WalletError::AuthorizationMismatch);
        }
        if now < self.valid_from || now > self.valid_until {
            return Err(WalletError::OutsideValidityWindow);
        }
        self.payment_key
            .valid_at(now)
            .map_err(|_| WalletError::OutsideValidityWindow)?;
        if payment.units > self.per_payment_ceiling {
            return Err(WalletError::ExceedsAuthorization);
        }
        Ok(())
    }

    fn period_index(&self, at: u64) -> u64 {
        at.saturating_sub(self.valid_from) / self.period_seconds
    }
}

/// One payment the obligor is asked to sign.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaymentRequest {
    pub payment_id: Identifier,
    pub stream_id: Identifier,
    pub installment_sequence: u64,
    pub units: u64,
    pub obligor_commitment: Commitment,
    pub payee_commitment: Commitment,
    pub settlement_asset_id: Identifier,
    pub due_at: u64,
    pub authorization_id: Identifier,
}

impl PaymentRequest {
    pub fn statement(&self) -> Result<Commitment, WalletError> {
        if [
            self.payment_id,
            self.stream_id,
            self.obligor_commitment,
            self.payee_commitment,
            self.settlement_asset_id,
            self.authorization_id,
        ]
        .contains(&ZERO)
            || self.installment_sequence == 0
            || self.units == 0
            || !valid_time(self.due_at)
        {
            return Err(WalletError::InvalidPayment);
        }
        Ok(digest(PAYMENT_DOMAIN, self)?)
    }
}

/// Handed to the obligor's signer. The signer signs `statement`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SigningRequest {
    pub payment: PaymentRequest,
    pub statement: Commitment,
    pub created_at: u64,
    pub payment_key: KeyRecord,
}

impl SigningRequest {
    /// Signs the request with the obligor's key. Kept here so a caller with
    /// the key in hand produces exactly the form [`ObligationWallet::enqueue`]
    /// verifies; a remote signer returns the same structure.
    pub fn sign(self, signer: &dyn Signer) -> Result<SignedPayment, WalletError> {
        if self.payment.statement()? != self.statement
            || signer.suite() != self.payment_key.suite
            || signer.public_key() != self.payment_key.public_key
            || self.payment_key.suite != PAYMENT_SUITE
            || self.payment_key.purpose != KeyPurpose::SettlementInstruction
            || self.payment_key.valid_at(self.created_at).is_err()
        {
            return Err(WalletError::InvalidSignature);
        }
        Ok(SignedPayment {
            payment: self.payment,
            key_id: self.payment_key.key_id,
            key_version: self.payment_key.key_version,
            signature: signer
                .sign(KeyPurpose::SettlementInstruction, &self.statement)
                .map_err(|_| WalletError::InvalidSignature)?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedPayment {
    pub payment: PaymentRequest,
    pub key_id: KeyId,
    pub key_version: u32,
    pub signature: Vec<u8>,
}

impl SignedPayment {
    pub fn verify(
        &self,
        authorization: &PreAuthorization,
        now: u64,
    ) -> Result<Commitment, WalletError> {
        let statement = self.payment.statement()?;
        authorization.validate()?;
        authorization.permits(&self.payment, now)?;
        if self.key_id != authorization.payment_key.key_id
            || self.key_version != authorization.payment_key.key_version
        {
            return Err(WalletError::InvalidSignature);
        }
        HybridVerifier
            .verify(
                KeyPurpose::SettlementInstruction,
                &authorization.payment_key.public_key,
                &statement,
                &self.signature,
            )
            .map_err(|_| WalletError::InvalidSignature)?;
        Ok(statement)
    }
}

/// Exponential backoff with a ceiling on both the delay and the attempts.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub base_delay_seconds: u64,
    pub max_delay_seconds: u64,
}

impl RetryPolicy {
    pub fn validate(&self) -> Result<(), WalletError> {
        if self.max_attempts == 0
            || self.base_delay_seconds == 0
            || self.max_delay_seconds < self.base_delay_seconds
        {
            return Err(WalletError::InvalidRetryPolicy);
        }
        Ok(())
    }

    /// Delay before attempt number `attempts + 1`.
    pub fn delay_after(&self, attempts: u32) -> u64 {
        let shift = attempts.saturating_sub(1).min(63);
        self.base_delay_seconds
            .checked_shl(shift)
            .unwrap_or(self.max_delay_seconds)
            .min(self.max_delay_seconds)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum QueueStatus {
    Pending,
    InFlight {
        attempt: u32,
        submitted_at: u64,
    },
    RetryScheduled {
        attempts: u32,
        next_attempt_at: u64,
        last_failure_digest: Commitment,
    },
    Acknowledged {
        receipt_digest: Commitment,
        settled_units: u64,
        finalized_at: u64,
    },
    Abandoned {
        attempts: u32,
        last_failure_digest: Commitment,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueueEntry {
    pub payment: SignedPayment,
    pub statement: Commitment,
    pub status: QueueStatus,
    pub enqueued_at: u64,
}

impl QueueEntry {
    fn is_live(&self) -> bool {
        !matches!(self.status, QueueStatus::Abandoned { .. })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnqueueOutcome {
    Accepted,
    /// The same payment was already queued; nothing changed.
    Duplicate,
}

/// What the authoritative side reports for one payment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementReceipt {
    pub payment_id: Identifier,
    pub receipt_digest: Commitment,
    pub settled_units: u64,
    pub finalized_at: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reconciliation {
    Matched,
    /// The same receipt was already applied; nothing changed.
    AlreadyReconciled,
    /// The authoritative side settled a different amount. The wallet records
    /// nothing: the discrepancy is for the obligor to resolve upstream.
    UnitsMismatch {
        expected: u64,
        settled: u64,
    },
    UnknownPayment,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObligationWallet {
    pub schedule: PaymentSchedule,
    pub retry: RetryPolicy,
    pub authorizations: BTreeMap<String, PreAuthorization>,
    pub queue: BTreeMap<String, QueueEntry>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
}

impl ObligationWallet {
    pub fn new(schedule: PaymentSchedule, retry: RetryPolicy) -> Result<Self, WalletError> {
        schedule.validate()?;
        retry.validate()?;
        Ok(Self {
            schedule,
            retry,
            authorizations: BTreeMap::new(),
            queue: BTreeMap::new(),
            receipts: BTreeMap::new(),
        })
    }

    /// Digest of the whole durable state.
    pub fn root(&self) -> Result<Commitment, WalletError> {
        self.validate()?;
        Ok(digest(WALLET_DOMAIN, self)?)
    }

    /// Rebuilds a wallet from its serialized form, refusing an inconsistent one.
    pub fn restore(snapshot: &str) -> Result<Self, WalletError> {
        let wallet: Self = serde_json::from_str(snapshot).map_err(|_| WalletError::InvalidState)?;
        wallet.validate()?;
        Ok(wallet)
    }

    pub fn snapshot(&self) -> Result<String, WalletError> {
        self.validate()?;
        serde_json::to_string(self).map_err(|_| WalletError::Encoding)
    }

    pub fn add_authorization(
        &mut self,
        authorization: PreAuthorization,
        now: u64,
    ) -> Result<(), WalletError> {
        authorization.validate()?;
        if authorization.stream_id != self.schedule.stream_id
            || authorization.obligor_commitment != self.schedule.obligor_commitment
            || authorization.payee_commitment != self.schedule.payee_commitment
            || authorization.settlement_asset_id != self.schedule.settlement_asset_id
        {
            return Err(WalletError::AuthorizationMismatch);
        }
        authorization
            .payment_key
            .valid_at(now)
            .map_err(|_| WalletError::OutsideValidityWindow)?;
        let key = id_key(&authorization.authorization_id);
        if self.authorizations.contains_key(&key) {
            return Err(WalletError::Replay);
        }
        self.authorizations.insert(key, authorization);
        Ok(())
    }

    pub fn entry(&self, payment_id: &Identifier) -> Result<&QueueEntry, WalletError> {
        self.queue
            .get(&id_key(payment_id))
            .ok_or(WalletError::UnknownPayment)
    }

    /// Prepares the payment of one installment under one authorization. The
    /// bounds are checked here so the signer is never asked to sign a payment
    /// the wallet would refuse to queue.
    pub fn prepare(
        &self,
        installment_sequence: u64,
        authorization_id: &Identifier,
        payment_id: Identifier,
        now: u64,
    ) -> Result<SigningRequest, WalletError> {
        let installment = self
            .schedule
            .installment(installment_sequence)
            .ok_or(WalletError::UnknownInstallment)?;
        let payment = PaymentRequest {
            payment_id,
            stream_id: self.schedule.stream_id,
            installment_sequence,
            units: installment.units,
            obligor_commitment: self.schedule.obligor_commitment,
            payee_commitment: self.schedule.payee_commitment,
            settlement_asset_id: self.schedule.settlement_asset_id,
            due_at: installment.due_at,
            authorization_id: *authorization_id,
        };
        let statement = payment.statement()?;
        self.check_bounds(&payment, now)?;
        let authorization = self
            .authorizations
            .get(&id_key(authorization_id))
            .ok_or(WalletError::UnknownAuthorization)?;
        Ok(SigningRequest {
            payment,
            statement,
            created_at: now,
            payment_key: authorization.payment_key.clone(),
        })
    }

    /// Queues a signed payment. Idempotent on `payment_id`: the same payment
    /// delivered twice is accepted once and reported as a duplicate after.
    pub fn enqueue(
        &mut self,
        signed: SignedPayment,
        now: u64,
    ) -> Result<EnqueueOutcome, WalletError> {
        let statement = signed.payment.statement()?;
        let key = id_key(&signed.payment.payment_id);
        if let Some(existing) = self.queue.get(&key) {
            return if existing.statement == statement && existing.payment == signed {
                Ok(EnqueueOutcome::Duplicate)
            } else {
                Err(WalletError::Replay)
            };
        }
        let authorization = self
            .authorizations
            .get(&id_key(&signed.payment.authorization_id))
            .ok_or(WalletError::UnknownAuthorization)?;
        signed.verify(authorization, now)?;
        let installment = self
            .schedule
            .installment(signed.payment.installment_sequence)
            .ok_or(WalletError::UnknownInstallment)?;
        if signed.payment.stream_id != self.schedule.stream_id
            || signed.payment.units != installment.units
            || signed.payment.due_at != installment.due_at
            || signed.payment.obligor_commitment != self.schedule.obligor_commitment
            || signed.payment.payee_commitment != self.schedule.payee_commitment
            || signed.payment.settlement_asset_id != self.schedule.settlement_asset_id
        {
            return Err(WalletError::ScheduleMismatch);
        }
        self.check_bounds(&signed.payment, now)?;
        self.queue.insert(
            key,
            QueueEntry {
                payment: signed,
                statement,
                status: QueueStatus::Pending,
                enqueued_at: now,
            },
        );
        Ok(EnqueueOutcome::Accepted)
    }

    /// The next payment to deliver: pending, or scheduled for a retry that is
    /// due, earliest installment first.
    pub fn next_ready(&self, now: u64) -> Option<&QueueEntry> {
        self.queue
            .values()
            .filter(|entry| match &entry.status {
                QueueStatus::Pending => true,
                QueueStatus::RetryScheduled {
                    next_attempt_at, ..
                } => *next_attempt_at <= now,
                _ => false,
            })
            .min_by_key(|entry| {
                (
                    entry.payment.payment.due_at,
                    entry.payment.payment.installment_sequence,
                )
            })
    }

    pub fn mark_in_flight(
        &mut self,
        payment_id: &Identifier,
        now: u64,
    ) -> Result<u32, WalletError> {
        let entry = self
            .queue
            .get_mut(&id_key(payment_id))
            .ok_or(WalletError::UnknownPayment)?;
        let attempt = match &entry.status {
            QueueStatus::Pending => 1,
            QueueStatus::RetryScheduled {
                attempts,
                next_attempt_at,
                ..
            } => {
                if *next_attempt_at > now {
                    return Err(WalletError::NotReady);
                }
                attempts + 1
            }
            _ => return Err(WalletError::NotReady),
        };
        entry.status = QueueStatus::InFlight {
            attempt,
            submitted_at: now,
        };
        Ok(attempt)
    }

    /// Records a delivery failure and schedules the retry, or abandons the
    /// payment once the policy's attempts are exhausted.
    pub fn mark_failed(
        &mut self,
        payment_id: &Identifier,
        failure_digest: Commitment,
        now: u64,
    ) -> Result<QueueStatus, WalletError> {
        if failure_digest == ZERO {
            return Err(WalletError::InvalidPayment);
        }
        let retry = self.retry;
        let entry = self
            .queue
            .get_mut(&id_key(payment_id))
            .ok_or(WalletError::UnknownPayment)?;
        let QueueStatus::InFlight { attempt, .. } = entry.status else {
            return Err(WalletError::NotReady);
        };
        entry.status = if attempt >= retry.max_attempts {
            QueueStatus::Abandoned {
                attempts: attempt,
                last_failure_digest: failure_digest,
            }
        } else {
            QueueStatus::RetryScheduled {
                attempts: attempt,
                next_attempt_at: now.saturating_add(retry.delay_after(attempt)),
                last_failure_digest: failure_digest,
            }
        };
        Ok(entry.status.clone())
    }

    /// Reconciles an authoritative receipt against the queue. A receipt for
    /// the queued amount acknowledges the payment; the same receipt again
    /// changes nothing; a different amount is reported and recorded nowhere.
    pub fn reconcile(&mut self, receipt: SettlementReceipt) -> Result<Reconciliation, WalletError> {
        if receipt.receipt_digest == ZERO || !valid_time(receipt.finalized_at) {
            return Err(WalletError::InvalidReceipt);
        }
        let key = id_key(&receipt.payment_id);
        let Some(entry) = self.queue.get_mut(&key) else {
            return Ok(Reconciliation::UnknownPayment);
        };
        if let QueueStatus::Acknowledged { receipt_digest, .. } = &entry.status {
            return if *receipt_digest == receipt.receipt_digest {
                Ok(Reconciliation::AlreadyReconciled)
            } else {
                Err(WalletError::Replay)
            };
        }
        if !entry.is_live() {
            return Err(WalletError::NotReady);
        }
        let expected = entry.payment.payment.units;
        if receipt.settled_units != expected {
            return Ok(Reconciliation::UnitsMismatch {
                expected,
                settled: receipt.settled_units,
            });
        }
        entry.status = QueueStatus::Acknowledged {
            receipt_digest: receipt.receipt_digest,
            settled_units: receipt.settled_units,
            finalized_at: receipt.finalized_at,
        };
        self.receipts.insert(key, receipt);
        Ok(Reconciliation::Matched)
    }

    /// Units the authoritative side has confirmed settled. Derived from
    /// receipts alone.
    pub fn settled_units(&self) -> Result<u64, WalletError> {
        self.receipts
            .values()
            .try_fold(0u64, |total, receipt| {
                total.checked_add(receipt.settled_units)
            })
            .ok_or(WalletError::ArithmeticOverflow)
    }

    /// Installments due by `now` for which no receipt has been reconciled.
    pub fn unsettled_due(&self, now: u64) -> Vec<Installment> {
        self.schedule
            .installments
            .iter()
            .filter(|installment| installment.due_at <= now)
            .filter(|installment| {
                !self.queue.values().any(|entry| {
                    entry.payment.payment.installment_sequence == installment.sequence
                        && matches!(entry.status, QueueStatus::Acknowledged { .. })
                })
            })
            .copied()
            .collect()
    }

    pub fn validate(&self) -> Result<(), WalletError> {
        self.schedule.validate()?;
        self.retry.validate()?;
        for (key, authorization) in &self.authorizations {
            authorization.validate()?;
            if key != &id_key(&authorization.authorization_id)
                || authorization.stream_id != self.schedule.stream_id
                || authorization.obligor_commitment != self.schedule.obligor_commitment
                || authorization.payee_commitment != self.schedule.payee_commitment
                || authorization.settlement_asset_id != self.schedule.settlement_asset_id
            {
                return Err(WalletError::InvalidState);
            }
        }
        for (key, entry) in &self.queue {
            let authorization = self
                .authorizations
                .get(&id_key(&entry.payment.payment.authorization_id))
                .ok_or(WalletError::InvalidState)?;
            let statement = entry
                .payment
                .verify(authorization, entry.enqueued_at)
                .map_err(|_| WalletError::InvalidState)?;
            let installment = self
                .schedule
                .installment(entry.payment.payment.installment_sequence)
                .ok_or(WalletError::InvalidState)?;
            if key != &id_key(&entry.payment.payment.payment_id)
                || statement != entry.statement
                || entry.payment.payment.units != installment.units
                || entry.payment.payment.due_at != installment.due_at
                || entry.payment.payment.stream_id != self.schedule.stream_id
                || entry.payment.payment.obligor_commitment != self.schedule.obligor_commitment
                || entry.payment.payment.payee_commitment != self.schedule.payee_commitment
                || entry.payment.payment.settlement_asset_id != self.schedule.settlement_asset_id
            {
                return Err(WalletError::InvalidState);
            }
            match (&entry.status, self.receipts.get(key)) {
                (
                    QueueStatus::Acknowledged {
                        receipt_digest,
                        settled_units,
                        finalized_at,
                    },
                    Some(receipt),
                ) if receipt.receipt_digest == *receipt_digest
                    && receipt.settled_units == *settled_units
                    && receipt.finalized_at == *finalized_at
                    && *settled_units == entry.payment.payment.units => {}
                (QueueStatus::Acknowledged { .. }, _) | (_, Some(_)) => {
                    return Err(WalletError::InvalidState)
                }
                _ => {}
            }
        }
        if self
            .receipts
            .keys()
            .any(|key| !self.queue.contains_key(key))
        {
            return Err(WalletError::InvalidState);
        }
        Ok(())
    }

    fn check_bounds(&self, payment: &PaymentRequest, now: u64) -> Result<(), WalletError> {
        let authorization = self
            .authorizations
            .get(&id_key(&payment.authorization_id))
            .ok_or(WalletError::UnknownAuthorization)?;
        authorization.permits(payment, now)?;
        let period = authorization.period_index(now);
        let spent = self
            .queue
            .values()
            .filter(|entry| {
                entry.is_live()
                    && entry.payment.payment.authorization_id == payment.authorization_id
                    && authorization.period_index(entry.enqueued_at) == period
            })
            .try_fold(0u64, |total, entry| {
                total.checked_add(entry.payment.payment.units)
            })
            .ok_or(WalletError::ArithmeticOverflow)?;
        if spent
            .checked_add(payment.units)
            .ok_or(WalletError::ArithmeticOverflow)?
            > authorization.period_ceiling
        {
            return Err(WalletError::ExceedsAuthorization);
        }
        if self.queue.values().any(|entry| {
            entry.is_live()
                && entry.payment.payment.installment_sequence == payment.installment_sequence
                && entry.payment.payment.payment_id != payment.payment_id
        }) {
            return Err(WalletError::InstallmentAlreadyQueued);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WalletError {
    #[error("wallet record encoding failed")]
    Encoding,
    #[error("wallet state is invalid")]
    InvalidState,
    #[error("payment schedule is invalid")]
    InvalidSchedule,
    #[error("installment is not in the schedule")]
    UnknownInstallment,
    #[error("an unsettled payment for this installment is already queued")]
    InstallmentAlreadyQueued,
    #[error("pre-authorization is invalid")]
    InvalidAuthorization,
    #[error("pre-authorization does not describe this schedule")]
    AuthorizationMismatch,
    #[error("pre-authorization is unknown")]
    UnknownAuthorization,
    #[error("payment exceeds the pre-authorization ceiling")]
    ExceedsAuthorization,
    #[error("payment is outside the pre-authorization window")]
    OutsideValidityWindow,
    #[error("payment request is invalid")]
    InvalidPayment,
    #[error("payment does not describe its scheduled installment")]
    ScheduleMismatch,
    #[error("payment signature is invalid")]
    InvalidSignature,
    #[error("payment is unknown to the queue")]
    UnknownPayment,
    #[error("queue entry is not in a state that allows this transition")]
    NotReady,
    #[error("settlement receipt is invalid")]
    InvalidReceipt,
    #[error("retry policy is invalid")]
    InvalidRetryPolicy,
    #[error("payment, authorization, or receipt was already recorded differently")]
    Replay,
    #[error("arithmetic overflow")]
    ArithmeticOverflow,
}

impl From<EncodingError> for WalletError {
    fn from(_: EncodingError) -> Self {
        Self::Encoding
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkfmi_crypto::{
        backend::{Ed25519Signer, MlDsa65Signer},
        hybrid::signature::HybridSigner,
        key::{KeyId, ParticipantId},
    };

    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn schedule() -> PaymentSchedule {
        PaymentSchedule {
            stream_id: id(20),
            obligor_commitment: id(21),
            payee_commitment: id(22),
            settlement_asset_id: id(23),
            installments: vec![
                Installment {
                    sequence: 1,
                    due_at: 100,
                    units: 40,
                },
                Installment {
                    sequence: 2,
                    due_at: 200,
                    units: 40,
                },
                Installment {
                    sequence: 3,
                    due_at: 300,
                    units: 40,
                },
            ],
        }
    }

    fn authorization() -> PreAuthorization {
        let signer = payment_signer();
        PreAuthorization {
            authorization_id: id(30),
            stream_id: id(20),
            obligor_commitment: id(21),
            payee_commitment: id(22),
            settlement_asset_id: id(23),
            payment_key: KeyRecord {
                participant_id: ParticipantId::new(id_key(&id(21))).unwrap(),
                key_id: KeyId::new("aethel-obligor-payment-test-v1").unwrap(),
                suite: PAYMENT_SUITE,
                key_version: 1,
                purpose: KeyPurpose::SettlementInstruction,
                public_key: signer.public_key(),
                not_before: 1,
                not_after: 20_000,
                revoked_at: None,
                rotation_proof: None,
                dekyx_binding: None,
            },
            per_payment_ceiling: 40,
            period_ceiling: 80,
            period_seconds: 1_000,
            valid_from: 1,
            valid_until: 10_000,
        }
    }

    fn payment_signer() -> HybridSigner {
        HybridSigner::new(
            Ed25519Signer::from_seed(&id(7)),
            MlDsa65Signer::from_seed(&id(8)),
        )
    }

    fn attacker_signer() -> HybridSigner {
        HybridSigner::new(
            Ed25519Signer::from_seed(&id(9)),
            MlDsa65Signer::from_seed(&id(10)),
        )
    }

    fn wallet() -> ObligationWallet {
        let mut wallet = ObligationWallet::new(
            schedule(),
            RetryPolicy {
                max_attempts: 3,
                base_delay_seconds: 10,
                max_delay_seconds: 15,
            },
        )
        .unwrap();
        wallet.add_authorization(authorization(), 1).unwrap();
        wallet
    }

    fn signed(wallet: &ObligationWallet, sequence: u64, payment: u8, now: u64) -> SignedPayment {
        wallet
            .prepare(sequence, &id(30), id(payment), now)
            .unwrap()
            .sign(&payment_signer())
            .unwrap()
    }

    #[test]
    fn projection_reads_the_schedule() {
        let wallet = wallet();
        assert_eq!(
            wallet
                .schedule
                .projection(150, 300)
                .iter()
                .map(|installment| installment.sequence)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert_eq!(wallet.schedule.total_units().unwrap(), 120);
        let mut broken = schedule();
        broken.installments[1].due_at = 100;
        assert_eq!(broken.validate(), Err(WalletError::InvalidSchedule));
    }

    #[test]
    fn pre_authorization_bounds_every_payment_and_every_period() {
        let mut wallet = wallet();
        wallet.enqueue(signed(&wallet, 1, 1, 50), 50).unwrap();
        wallet.enqueue(signed(&wallet, 2, 2, 60), 60).unwrap();
        assert_eq!(
            wallet.prepare(3, &id(30), id(3), 70),
            Err(WalletError::ExceedsAuthorization)
        );
        // The next period opens the budget again.
        assert!(wallet.prepare(3, &id(30), id(3), 1_100).is_ok());
        let mut small = authorization();
        small.authorization_id = id(31);
        small.per_payment_ceiling = 39;
        small.period_ceiling = 39;
        wallet.add_authorization(small, 1).unwrap();
        assert_eq!(
            wallet.prepare(3, &id(31), id(3), 70),
            Err(WalletError::ExceedsAuthorization)
        );
        assert_eq!(
            wallet.prepare(3, &id(30), id(3), 10_001),
            Err(WalletError::OutsideValidityWindow)
        );
    }

    #[test]
    fn duplicate_delivery_is_idempotent_and_a_forged_payment_is_refused() {
        let mut wallet = wallet();
        let payment = signed(&wallet, 1, 1, 50);
        assert_eq!(
            wallet.enqueue(payment.clone(), 50),
            Ok(EnqueueOutcome::Accepted)
        );
        assert_eq!(
            wallet.enqueue(payment.clone(), 51),
            Ok(EnqueueOutcome::Duplicate)
        );
        assert_eq!(wallet.queue.len(), 1);
        let mut forged = payment.clone();
        forged.payment.units = 1;
        assert_eq!(wallet.enqueue(forged, 52), Err(WalletError::Replay));
        let mut different = wallet
            .prepare(2, &id(30), id(1), 52)
            .unwrap()
            .sign(&payment_signer())
            .unwrap();
        different.payment.payment_id = id(1);
        assert_eq!(wallet.enqueue(different, 52), Err(WalletError::Replay));
        assert_eq!(
            wallet.prepare(1, &id(30), id(9), 53),
            Err(WalletError::InstallmentAlreadyQueued)
        );
    }

    #[test]
    fn the_queue_retries_with_backoff_and_then_abandons() {
        let mut wallet = wallet();
        wallet.enqueue(signed(&wallet, 1, 1, 50), 50).unwrap();
        assert_eq!(wallet.mark_in_flight(&id(1), 60), Ok(1));
        assert!(wallet.next_ready(60).is_none());
        let status = wallet.mark_failed(&id(1), id(99), 60).unwrap();
        assert_eq!(
            status,
            QueueStatus::RetryScheduled {
                attempts: 1,
                next_attempt_at: 70,
                last_failure_digest: id(99),
            }
        );
        assert!(wallet.next_ready(69).is_none());
        assert_eq!(
            wallet.mark_in_flight(&id(1), 69),
            Err(WalletError::NotReady)
        );
        assert_eq!(wallet.mark_in_flight(&id(1), 70), Ok(2));
        wallet.mark_failed(&id(1), id(99), 70).unwrap();
        assert_eq!(wallet.mark_in_flight(&id(1), 85), Ok(3));
        assert_eq!(
            wallet.mark_failed(&id(1), id(99), 85).unwrap(),
            QueueStatus::Abandoned {
                attempts: 3,
                last_failure_digest: id(99),
            }
        );
        // An abandoned payment frees the installment for a fresh payment.
        assert!(wallet.prepare(1, &id(30), id(2), 90).is_ok());
    }

    #[test]
    fn reconciliation_reports_only_what_the_receipt_says() {
        let mut wallet = wallet();
        wallet.enqueue(signed(&wallet, 1, 1, 50), 50).unwrap();
        wallet.mark_in_flight(&id(1), 60).unwrap();
        assert_eq!(wallet.settled_units().unwrap(), 0);
        let receipt = SettlementReceipt {
            payment_id: id(1),
            receipt_digest: id(80),
            settled_units: 40,
            finalized_at: 65,
        };
        let mut short = receipt.clone();
        short.settled_units = 30;
        assert_eq!(
            wallet.reconcile(short),
            Ok(Reconciliation::UnitsMismatch {
                expected: 40,
                settled: 30
            })
        );
        assert_eq!(wallet.settled_units().unwrap(), 0);
        assert_eq!(
            wallet.reconcile(receipt.clone()),
            Ok(Reconciliation::Matched)
        );
        assert_eq!(
            wallet.reconcile(receipt.clone()),
            Ok(Reconciliation::AlreadyReconciled)
        );
        assert_eq!(wallet.settled_units().unwrap(), 40);
        let mut other = receipt;
        other.payment_id = id(5);
        assert_eq!(wallet.reconcile(other), Ok(Reconciliation::UnknownPayment));
        assert_eq!(
            wallet
                .unsettled_due(250)
                .iter()
                .map(|installment| installment.sequence)
                .collect::<Vec<_>>(),
            vec![2]
        );
    }

    #[test]
    fn the_queue_survives_a_snapshot() {
        let mut wallet = wallet();
        wallet.enqueue(signed(&wallet, 1, 1, 50), 50).unwrap();
        wallet.mark_in_flight(&id(1), 60).unwrap();
        wallet.mark_failed(&id(1), id(99), 60).unwrap();
        let snapshot = wallet.snapshot().unwrap();
        let restored = ObligationWallet::restore(&snapshot).unwrap();
        assert_eq!(restored, wallet);
        assert_eq!(restored.root().unwrap(), wallet.root().unwrap());
        assert_eq!(
            restored
                .next_ready(70)
                .map(|entry| entry.payment.payment.payment_id),
            Some(id(1))
        );
        let mut tampered: ObligationWallet = serde_json::from_str(&snapshot).unwrap();
        tampered
            .queue
            .values_mut()
            .next()
            .unwrap()
            .payment
            .payment
            .units = 1;
        let tampered = serde_json::to_string(&tampered).unwrap();
        assert!(ObligationWallet::restore(&tampered).is_err());
    }

    #[test]
    fn authorization_pins_a_hybrid_key_to_the_schedule_obligor() {
        let retry = RetryPolicy {
            max_attempts: 3,
            base_delay_seconds: 10,
            max_delay_seconds: 15,
        };
        let new_wallet = || ObligationWallet::new(schedule(), retry).unwrap();

        let mut wrong_obligor = authorization();
        wrong_obligor.obligor_commitment = id(44);
        wrong_obligor.payment_key.participant_id =
            ParticipantId::new(id_key(&wrong_obligor.obligor_commitment)).unwrap();
        assert_eq!(
            new_wallet().add_authorization(wrong_obligor, 1),
            Err(WalletError::AuthorizationMismatch)
        );

        let mut wrong_participant = authorization();
        wrong_participant.payment_key.participant_id =
            ParticipantId::new("another-obligor").unwrap();
        assert_eq!(
            new_wallet().add_authorization(wrong_participant, 1),
            Err(WalletError::InvalidAuthorization)
        );

        let mut wrong_purpose = authorization();
        wrong_purpose.payment_key.purpose = KeyPurpose::Quote;
        assert_eq!(
            new_wallet().add_authorization(wrong_purpose, 1),
            Err(WalletError::InvalidAuthorization)
        );

        let mut wrong_suite = authorization();
        wrong_suite.payment_key.suite = Suite::new(SuiteId::MlDsa65);
        assert_eq!(
            new_wallet().add_authorization(wrong_suite, 1),
            Err(WalletError::InvalidAuthorization)
        );

        let mut not_yet_valid = authorization();
        not_yet_valid.payment_key.not_before = 2;
        assert_eq!(
            new_wallet().add_authorization(not_yet_valid, 1),
            Err(WalletError::OutsideValidityWindow)
        );
        let mut expired = authorization();
        expired.payment_key.not_after = 2;
        assert_eq!(
            new_wallet().add_authorization(expired, 2),
            Err(WalletError::OutsideValidityWindow)
        );
        let mut revoked = authorization();
        revoked.payment_key.revoked_at = Some(1);
        assert_eq!(
            new_wallet().add_authorization(revoked, 1),
            Err(WalletError::OutsideValidityWindow)
        );

        let mut unavailable = wallet();
        unavailable
            .authorizations
            .get_mut(&id_key(&id(30)))
            .unwrap()
            .payment_key
            .revoked_at = Some(50);
        assert_eq!(
            unavailable.prepare(1, &id(30), id(1), 50),
            Err(WalletError::OutsideValidityWindow)
        );
    }

    #[test]
    fn only_the_registered_key_and_both_signature_components_are_accepted() {
        let mut wallet = wallet();
        let request = wallet.prepare(1, &id(30), id(1), 50).unwrap();
        assert_eq!(
            request.clone().sign(&attacker_signer()),
            Err(WalletError::InvalidSignature)
        );
        let authorization = wallet.authorizations.get(&id_key(&id(30))).unwrap().clone();
        let forged = SignedPayment {
            payment: request.payment.clone(),
            key_id: authorization.payment_key.key_id.clone(),
            key_version: authorization.payment_key.key_version,
            signature: attacker_signer()
                .sign(KeyPurpose::SettlementInstruction, &request.statement)
                .unwrap(),
        };
        assert_eq!(
            wallet.enqueue(forged, 50),
            Err(WalletError::InvalidSignature)
        );

        let signed = request.sign(&payment_signer()).unwrap();
        assert_eq!(signed.signature.len(), 64 + 3_309);
        for at in [0, 64] {
            let mut altered = signed.clone();
            altered.signature[at] ^= 1;
            assert_eq!(
                altered.verify(&authorization, 50),
                Err(WalletError::InvalidSignature)
            );
        }
        let mut truncated = signed.clone();
        truncated.signature.pop();
        assert_eq!(
            truncated.verify(&authorization, 50),
            Err(WalletError::InvalidSignature)
        );
        let mut trailing = signed.clone();
        trailing.signature.push(0);
        assert_eq!(
            trailing.verify(&authorization, 50),
            Err(WalletError::InvalidSignature)
        );
        let mut wrong_id = signed.clone();
        wrong_id.key_id = KeyId::new("another-key").unwrap();
        assert_eq!(
            wrong_id.verify(&authorization, 50),
            Err(WalletError::InvalidSignature)
        );
        let mut wrong_version = signed;
        wrong_version.key_version += 1;
        assert_eq!(
            wrong_version.verify(&authorization, 50),
            Err(WalletError::InvalidSignature)
        );
    }

    #[test]
    fn retry_and_restore_reuse_the_exact_randomized_signed_wire() {
        let mut authorization = authorization();
        authorization.payment_key.not_after = 51;
        let mut wallet = ObligationWallet::new(
            schedule(),
            RetryPolicy {
                max_attempts: 3,
                base_delay_seconds: 10,
                max_delay_seconds: 15,
            },
        )
        .unwrap();
        wallet.add_authorization(authorization, 1).unwrap();
        let request = wallet.prepare(1, &id(30), id(1), 50).unwrap();
        let first = request.clone().sign(&payment_signer()).unwrap();
        let resigned = request.sign(&payment_signer()).unwrap();
        assert_ne!(first.signature, resigned.signature);
        let first_wire = serde_json::to_vec(&first).unwrap();
        assert_eq!(
            wallet.enqueue(first.clone(), 50),
            Ok(EnqueueOutcome::Accepted)
        );
        assert_eq!(
            wallet.enqueue(first.clone(), 500),
            Ok(EnqueueOutcome::Duplicate)
        );
        assert_eq!(wallet.enqueue(resigned, 500), Err(WalletError::Replay));

        let snapshot = wallet.snapshot().unwrap();
        let mut restored = ObligationWallet::restore(&snapshot).unwrap();
        assert_eq!(restored.entry(&id(1)).unwrap().payment, first);
        assert_eq!(
            serde_json::to_vec(&restored.entry(&id(1)).unwrap().payment).unwrap(),
            first_wire
        );
        assert_eq!(
            restored.enqueue(first, 1_000),
            Ok(EnqueueOutcome::Duplicate)
        );
    }

    #[test]
    fn legacy_self_signed_wire_and_invalid_historical_key_are_rejected() {
        let wallet = wallet();
        let signed = signed(&wallet, 1, 1, 50);
        let mut legacy = serde_json::to_value(&signed).unwrap();
        let fields = legacy.as_object_mut().unwrap();
        fields.remove("keyId");
        fields.remove("keyVersion");
        fields.insert(
            "signerPublicKey".into(),
            serde_json::to_value([7_u8; 32]).unwrap(),
        );
        assert!(serde_json::from_value::<SignedPayment>(legacy).is_err());

        let mut accepted = wallet;
        accepted.enqueue(signed, 50).unwrap();
        let mut invalid_history = accepted.clone();
        invalid_history
            .authorizations
            .get_mut(&id_key(&id(30)))
            .unwrap()
            .payment_key
            .revoked_at = Some(50);
        assert!(
            ObligationWallet::restore(&serde_json::to_string(&invalid_history).unwrap()).is_err()
        );

        let mut legacy_snapshot = serde_json::to_value(accepted).unwrap();
        let authorization_key = id_key(&id(30));
        let stored = legacy_snapshot["authorizations"]
            .get_mut(&authorization_key)
            .unwrap()
            .as_object_mut()
            .unwrap();
        stored.remove("obligorCommitment");
        stored.remove("paymentKey");
        assert!(
            ObligationWallet::restore(&serde_json::to_string(&legacy_snapshot).unwrap()).is_err()
        );
    }
}
