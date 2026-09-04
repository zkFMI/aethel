//! The circulation boundary of a receivable token.
//!
//! Distribution decides whether a unit of a receivable token may move and
//! packages the result for settlement. It does not price, match, or hold an
//! order book: a [`CirculationRequest`] is admitted against the token series'
//! transfer restriction and handed to a venue (a bilateral counterparty, QOMM,
//! OCLOB, or an external venue) as a typed [`VenueHandoff`]; the venue returns
//! a [`VenueFill`]; distribution validates the fill against the request and
//! emits a [`SettlementContext`] whose statement digest a host binds into its
//! zkPI and DeFMI settlement. The settlement outcome is recorded from the
//! host's receipt. Nothing here imports a venue's business logic.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use aethel_tokenization::{TokenSeries, TokenSeriesStatus, TransferRestriction};
use aethel_types::{digest, id_key, valid_time, Commitment, EncodingError, Identifier, ZERO};

const CIRCULATION_REQUEST_DOMAIN: &[u8] = b"AETHEL:CIRCULATION-REQUEST:v1";
const VENUE_FILL_DOMAIN: &[u8] = b"AETHEL:VENUE-FILL:v1";
const SETTLEMENT_CONTEXT_DOMAIN: &[u8] = b"AETHEL:SETTLEMENT-CONTEXT:v1";
const SETTLEMENT_NULLIFIER_DOMAIN: &[u8] = b"AETHEL:SETTLEMENT-NULLIFIER:v1";
const TRANSFER_RESTRICTION_DOMAIN: &[u8] = b"AETHEL:TRANSFER-RESTRICTION:v1";
const DISTRIBUTION_BOOK_DOMAIN: &[u8] = b"AETHEL:DISTRIBUTION-BOOK:v1";

/// Where a request is circulated. The venue owns discovery and matching;
/// distribution owns eligibility and the settlement binding.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Venue {
    /// A named counterparty; no discovery.
    Bilateral,
    /// Query-oblivious market making.
    Qomm,
    /// The oblivious central limit order book.
    Oclob,
    External {
        venue_id: Identifier,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    Sell,
    Buy,
}

/// A holder's or buyer's request to circulate units of one issuance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CirculationRequest {
    pub request_id: Identifier,
    pub operation_id: Identifier,
    pub token_series_id: Identifier,
    pub series_id: Identifier,
    pub issuance_id: Identifier,
    pub receivable_asset_id: Identifier,
    pub cash_asset_id: Identifier,
    pub units: u64,
    pub side: Side,
    pub initiator_commitment: Commitment,
    /// Required for a bilateral request; absent otherwise, the venue names it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counterparty_commitment: Option<Commitment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit_price_commitment: Option<Commitment>,
    pub venue: Venue,
    /// Digest of the DeKYX eligibility evidence for a qualified-holder series.
    /// The evidence itself is verified by the host against DeKYX; this only
    /// binds which evidence the admission relied on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eligibility_attestation_digest: Option<Commitment>,
    pub valid_until: u64,
}

impl CirculationRequest {
    pub fn statement(&self) -> Result<Commitment, DistributionError> {
        if [
            self.request_id,
            self.operation_id,
            self.token_series_id,
            self.series_id,
            self.issuance_id,
            self.receivable_asset_id,
            self.cash_asset_id,
            self.initiator_commitment,
        ]
        .contains(&ZERO)
            || self.counterparty_commitment == Some(ZERO)
            || self.counterparty_commitment == Some(self.initiator_commitment)
            || self.limit_price_commitment == Some(ZERO)
            || self.eligibility_attestation_digest == Some(ZERO)
            || matches!(self.venue, Venue::External { venue_id } if venue_id == ZERO)
            || self.units == 0
            || !valid_time(self.valid_until)
        {
            return Err(DistributionError::InvalidRequest);
        }
        Ok(digest(CIRCULATION_REQUEST_DOMAIN, self)?)
    }
}

/// What distribution gives the venue: the request digest and nothing about
/// the token beyond what the request already states.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VenueHandoff {
    pub request_id: Identifier,
    pub venue: Venue,
    pub request_digest: Commitment,
    pub handed_at: u64,
}

/// What the venue returns: a (possibly partial) fill of one request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VenueFill {
    pub fill_id: Identifier,
    pub request_id: Identifier,
    pub venue: Venue,
    pub units: u64,
    pub counterparty_commitment: Commitment,
    pub price_commitment: Commitment,
    /// The venue's own evidence for the fill (a QOMM quote proof digest, an
    /// OCLOB match digest, a bilateral acceptance). Opaque here.
    pub venue_evidence_digest: Commitment,
    pub filled_at: u64,
}

impl VenueFill {
    pub fn statement(&self) -> Result<Commitment, DistributionError> {
        if [
            self.fill_id,
            self.request_id,
            self.counterparty_commitment,
            self.price_commitment,
            self.venue_evidence_digest,
        ]
        .contains(&ZERO)
            || self.units == 0
            || !valid_time(self.filled_at)
        {
            return Err(DistributionError::InvalidFill);
        }
        Ok(digest(VENUE_FILL_DOMAIN, self)?)
    }
}

/// The settlement binding: everything a zkPI issuer and DeFMI need to settle
/// one fill, with no reference to how the venue arrived at it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SettlementContext {
    pub context_id: Identifier,
    pub request_id: Identifier,
    pub fill_id: Identifier,
    pub venue: Venue,
    pub token_series_id: Identifier,
    pub series_id: Identifier,
    pub issuance_id: Identifier,
    pub receivable_asset_id: Identifier,
    pub cash_asset_id: Identifier,
    pub units: u64,
    pub seller_commitment: Commitment,
    pub buyer_commitment: Commitment,
    pub price_commitment: Commitment,
    pub venue_evidence_digest: Commitment,
    /// Digest of the series' transfer restriction at admission, so the ledger
    /// lock the settlement applies is the one distribution evaluated.
    pub transfer_restriction_digest: Commitment,
    pub deadline: u64,
    pub nullifier: Identifier,
}

impl SettlementContext {
    pub fn statement(&self) -> Result<Commitment, DistributionError> {
        if [
            self.context_id,
            self.request_id,
            self.fill_id,
            self.token_series_id,
            self.series_id,
            self.issuance_id,
            self.receivable_asset_id,
            self.cash_asset_id,
            self.seller_commitment,
            self.buyer_commitment,
            self.price_commitment,
            self.venue_evidence_digest,
            self.transfer_restriction_digest,
            self.nullifier,
        ]
        .contains(&ZERO)
            || self.seller_commitment == self.buyer_commitment
            || self.units == 0
            || !valid_time(self.deadline)
        {
            return Err(DistributionError::InvalidContext);
        }
        Ok(digest(SETTLEMENT_CONTEXT_DOMAIN, self)?)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum SettlementOutcome {
    Settled {
        receipt_digest: Commitment,
        finalized_at: u64,
    },
    Expired {
        at: u64,
    },
    Rejected {
        reason_digest: Commitment,
        at: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdmittedRequest {
    pub request: CirculationRequest,
    pub handoff: VenueHandoff,
    pub transfer_restriction_digest: Commitment,
    pub filled_units: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DistributionBook {
    pub requests: BTreeMap<String, AdmittedRequest>,
    pub contexts: BTreeMap<String, SettlementContext>,
    pub outcomes: BTreeMap<String, SettlementOutcome>,
    pub used_operations: BTreeSet<String>,
    pub used_nullifiers: BTreeSet<String>,
}

/// Digest of a transfer restriction, as bound into a settlement context.
pub fn transfer_restriction_digest(
    restriction: &TransferRestriction,
) -> Result<Commitment, DistributionError> {
    Ok(digest(TRANSFER_RESTRICTION_DOMAIN, restriction)?)
}

impl DistributionBook {
    pub fn root(&self) -> Result<Commitment, DistributionError> {
        self.validate()?;
        Ok(digest(DISTRIBUTION_BOOK_DOMAIN, self)?)
    }

    pub fn request(&self, request_id: &Identifier) -> Result<&AdmittedRequest, DistributionError> {
        self.requests
            .get(&id_key(request_id))
            .ok_or(DistributionError::UnknownRequest)
    }

    pub fn context(
        &self,
        context_id: &Identifier,
    ) -> Result<&SettlementContext, DistributionError> {
        self.contexts
            .get(&id_key(context_id))
            .ok_or(DistributionError::UnknownContext)
    }

    pub fn outcome(&self, context_id: &Identifier) -> Option<&SettlementOutcome> {
        self.outcomes.get(&id_key(context_id))
    }

    /// Admits a request against the token series the caller took from the
    /// tokenization book, and hands it to the venue.
    pub fn admit(
        &mut self,
        request: CirculationRequest,
        series: &TokenSeries,
        now: u64,
    ) -> Result<VenueHandoff, DistributionError> {
        let request_digest = request.statement()?;
        if series.token_series_id != request.token_series_id
            || series.series_id != request.series_id
            || series.receivable_asset_id != request.receivable_asset_id
        {
            return Err(DistributionError::SeriesMismatch);
        }
        if series.status != TokenSeriesStatus::Open || now > series.maturity {
            return Err(DistributionError::SeriesUnavailable);
        }
        if now > request.valid_until || request.valid_until > series.maturity {
            return Err(DistributionError::OutsideValidityWindow);
        }
        match (&request.venue, request.counterparty_commitment) {
            (Venue::Bilateral, None) => return Err(DistributionError::InvalidRequest),
            (Venue::Bilateral, Some(_)) | (_, None) => {}
            (_, Some(_)) => return Err(DistributionError::InvalidRequest),
        }
        match &series.transfer_restriction {
            TransferRestriction::NonTransferable => return Err(DistributionError::NotTransferable),
            TransferRestriction::IssuerRepurchaseOnly { issuer_commitment } => {
                let issuer_is_buyer = match request.side {
                    Side::Sell => request.counterparty_commitment == Some(*issuer_commitment),
                    Side::Buy => request.initiator_commitment == *issuer_commitment,
                };
                if request.venue != Venue::Bilateral || !issuer_is_buyer {
                    return Err(DistributionError::NotTransferable);
                }
            }
            TransferRestriction::QualifiedHolders { .. } => {
                if request.eligibility_attestation_digest.is_none() {
                    return Err(DistributionError::EligibilityRequired);
                }
            }
            TransferRestriction::Unrestricted => {}
        }
        let key = id_key(&request.request_id);
        if self.requests.contains_key(&key) {
            return Err(DistributionError::Replay);
        }
        self.consume_operation(&request.operation_id)?;
        let handoff = VenueHandoff {
            request_id: request.request_id,
            venue: request.venue,
            request_digest,
            handed_at: now,
        };
        self.requests.insert(
            key,
            AdmittedRequest {
                request,
                handoff: handoff.clone(),
                transfer_restriction_digest: transfer_restriction_digest(
                    &series.transfer_restriction,
                )?,
                filled_units: 0,
            },
        );
        Ok(handoff)
    }

    /// Validates a venue fill against its admitted request and emits the
    /// settlement context. Partial fills are allowed up to the requested
    /// units; every fill produces one context with its own nullifier.
    pub fn accept_fill(
        &mut self,
        fill: VenueFill,
        now: u64,
    ) -> Result<SettlementContext, DistributionError> {
        fill.statement()?;
        let admitted = self.request(&fill.request_id)?;
        let request = &admitted.request;
        if fill.venue != request.venue
            || fill.counterparty_commitment == request.initiator_commitment
            || request
                .counterparty_commitment
                .is_some_and(|counterparty| counterparty != fill.counterparty_commitment)
        {
            return Err(DistributionError::FillMismatch);
        }
        if fill.filled_at > now || now > request.valid_until {
            return Err(DistributionError::OutsideValidityWindow);
        }
        if admitted
            .filled_units
            .checked_add(fill.units)
            .ok_or(DistributionError::ArithmeticOverflow)?
            > request.units
        {
            return Err(DistributionError::OverFilled);
        }
        let (seller_commitment, buyer_commitment) = match request.side {
            Side::Sell => (request.initiator_commitment, fill.counterparty_commitment),
            Side::Buy => (fill.counterparty_commitment, request.initiator_commitment),
        };
        let nullifier = digest(
            SETTLEMENT_NULLIFIER_DOMAIN,
            &(request.request_id, fill.fill_id),
        )?;
        let context = SettlementContext {
            context_id: digest(SETTLEMENT_CONTEXT_DOMAIN, &(fill.fill_id, nullifier))?,
            request_id: request.request_id,
            fill_id: fill.fill_id,
            venue: request.venue,
            token_series_id: request.token_series_id,
            series_id: request.series_id,
            issuance_id: request.issuance_id,
            receivable_asset_id: request.receivable_asset_id,
            cash_asset_id: request.cash_asset_id,
            units: fill.units,
            seller_commitment,
            buyer_commitment,
            price_commitment: fill.price_commitment,
            venue_evidence_digest: fill.venue_evidence_digest,
            transfer_restriction_digest: admitted.transfer_restriction_digest,
            deadline: request.valid_until,
            nullifier,
        };
        context.statement()?;
        let nullifier_key = id_key(&nullifier);
        let context_key = id_key(&context.context_id);
        if self.used_nullifiers.contains(&nullifier_key) || self.contexts.contains_key(&context_key)
        {
            return Err(DistributionError::Replay);
        }
        self.used_nullifiers.insert(nullifier_key);
        self.requests
            .get_mut(&id_key(&fill.request_id))
            .expect("checked request")
            .filled_units += fill.units;
        self.contexts.insert(context_key, context.clone());
        Ok(context)
    }

    /// Records what the host observed for a context. A settlement after the
    /// deadline is not a settlement; an expiry before it is not an expiry.
    pub fn record_outcome(
        &mut self,
        context_id: &Identifier,
        outcome: SettlementOutcome,
    ) -> Result<(), DistributionError> {
        let context = self.context(context_id)?;
        let key = id_key(context_id);
        if self.outcomes.contains_key(&key) {
            return Err(DistributionError::Replay);
        }
        let consistent = match &outcome {
            SettlementOutcome::Settled {
                receipt_digest,
                finalized_at,
            } => {
                *receipt_digest != ZERO
                    && valid_time(*finalized_at)
                    && *finalized_at <= context.deadline
            }
            SettlementOutcome::Expired { at } => *at > context.deadline,
            SettlementOutcome::Rejected { reason_digest, at } => {
                *reason_digest != ZERO && valid_time(*at)
            }
        };
        if !consistent {
            return Err(DistributionError::InvalidOutcome);
        }
        let released = context.units;
        if !matches!(outcome, SettlementOutcome::Settled { .. }) {
            // The units return to the request's unfilled balance so the
            // venue may fill them again before the request expires.
            let admitted = self
                .requests
                .get_mut(&id_key(&context.request_id))
                .expect("context names an admitted request");
            admitted.filled_units -= released;
        }
        self.outcomes.insert(key, outcome);
        Ok(())
    }

    pub fn validate(&self) -> Result<(), DistributionError> {
        let mut filled: BTreeMap<String, u64> = BTreeMap::new();
        for (key, admitted) in &self.requests {
            let digest = admitted.request.statement()?;
            if key != &id_key(&admitted.request.request_id)
                || admitted.handoff.request_id != admitted.request.request_id
                || admitted.handoff.venue != admitted.request.venue
                || admitted.handoff.request_digest != digest
                || admitted.transfer_restriction_digest == ZERO
                || admitted.filled_units > admitted.request.units
                || !self
                    .used_operations
                    .contains(&id_key(&admitted.request.operation_id))
            {
                return Err(DistributionError::InvalidState);
            }
            filled.insert(key.clone(), 0);
        }
        for (key, context) in &self.contexts {
            context.statement()?;
            let admitted = self.request(&context.request_id)?;
            if key != &id_key(&context.context_id)
                || !self.used_nullifiers.contains(&id_key(&context.nullifier))
                || context.transfer_restriction_digest != admitted.transfer_restriction_digest
                || context.deadline != admitted.request.valid_until
            {
                return Err(DistributionError::InvalidState);
            }
            let settled_or_open = match self.outcomes.get(key) {
                None | Some(SettlementOutcome::Settled { .. }) => true,
                Some(_) => false,
            };
            if settled_or_open {
                *filled
                    .get_mut(&id_key(&context.request_id))
                    .expect("request exists") += context.units;
            }
        }
        for (key, admitted) in &self.requests {
            if filled[key] != admitted.filled_units {
                return Err(DistributionError::InvalidState);
            }
        }
        if self.used_nullifiers.len() != self.contexts.len()
            || self
                .outcomes
                .keys()
                .any(|key| !self.contexts.contains_key(key))
        {
            return Err(DistributionError::InvalidState);
        }
        Ok(())
    }

    fn consume_operation(&mut self, operation_id: &Identifier) -> Result<(), DistributionError> {
        let key = id_key(operation_id);
        if *operation_id == ZERO || self.used_operations.contains(&key) {
            return Err(DistributionError::Replay);
        }
        self.used_operations.insert(key);
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DistributionError {
    #[error("distribution record encoding failed")]
    Encoding,
    #[error("distribution state is invalid")]
    InvalidState,
    #[error("circulation request is invalid")]
    InvalidRequest,
    #[error("circulation request is unknown")]
    UnknownRequest,
    #[error("token series does not describe the request")]
    SeriesMismatch,
    #[error("token series is frozen, redeemed, or past maturity")]
    SeriesUnavailable,
    #[error("token series does not permit this transfer")]
    NotTransferable,
    #[error("token series admits qualified holders only; eligibility evidence is required")]
    EligibilityRequired,
    #[error("venue fill is invalid")]
    InvalidFill,
    #[error("venue fill does not describe the admitted request")]
    FillMismatch,
    #[error("fills exceed the requested units")]
    OverFilled,
    #[error("settlement context is invalid")]
    InvalidContext,
    #[error("settlement context is unknown")]
    UnknownContext,
    #[error("settlement outcome is inconsistent with the context deadline")]
    InvalidOutcome,
    #[error("request, fill, or outcome is outside its validity window")]
    OutsideValidityWindow,
    #[error("operation, request, or nullifier was already used")]
    Replay,
    #[error("arithmetic overflow")]
    ArithmeticOverflow,
}

impl From<EncodingError> for DistributionError {
    fn from(_: EncodingError) -> Self {
        Self::Encoding
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aethel_tokenization::RedemptionCondition;

    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn series(restriction: TransferRestriction) -> TokenSeries {
        TokenSeries {
            token_series_id: id(60),
            series_id: id(34),
            receivable_asset_id: id(35),
            aethel_domain_id: id(39),
            issuer_participant_id: id(36),
            units_per_receivable: 100,
            issuance_cap_units: 1_000,
            tranches: Vec::new(),
            transfer_restriction: restriction,
            redemption: vec![RedemptionCondition::StreamClosed],
            valid_from: 1,
            maturity: 1_000,
            status: TokenSeriesStatus::Open,
        }
    }

    fn request(venue: Venue, counterparty: Option<[u8; 32]>) -> CirculationRequest {
        CirculationRequest {
            request_id: id(70),
            operation_id: id(71),
            token_series_id: id(60),
            series_id: id(34),
            issuance_id: id(91),
            receivable_asset_id: id(35),
            cash_asset_id: id(23),
            units: 50,
            side: Side::Sell,
            initiator_commitment: id(200),
            counterparty_commitment: counterparty,
            limit_price_commitment: None,
            venue,
            eligibility_attestation_digest: None,
            valid_until: 500,
        }
    }

    fn fill(fill_id: u8, units: u64, counterparty: u8) -> VenueFill {
        VenueFill {
            fill_id: id(fill_id),
            request_id: id(70),
            venue: Venue::Qomm,
            units,
            counterparty_commitment: id(counterparty),
            price_commitment: id(150),
            venue_evidence_digest: id(151),
            filled_at: 100,
        }
    }

    #[test]
    fn a_non_transferable_series_admits_nothing() {
        let mut book = DistributionBook::default();
        assert_eq!(
            book.admit(
                request(Venue::Qomm, None),
                &series(TransferRestriction::NonTransferable),
                60
            ),
            Err(DistributionError::NotTransferable)
        );
    }

    #[test]
    fn issuer_repurchase_only_allows_the_issuer_to_buy_bilaterally() {
        let restriction = TransferRestriction::IssuerRepurchaseOnly {
            issuer_commitment: id(36),
        };
        let mut book = DistributionBook::default();
        assert_eq!(
            book.admit(request(Venue::Qomm, None), &series(restriction.clone()), 60),
            Err(DistributionError::NotTransferable)
        );
        assert_eq!(
            book.admit(
                request(Venue::Bilateral, Some(id(201))),
                &series(restriction.clone()),
                60
            ),
            Err(DistributionError::NotTransferable)
        );
        book.admit(
            request(Venue::Bilateral, Some(id(36))),
            &series(restriction),
            60,
        )
        .unwrap();
    }

    #[test]
    fn qualified_holder_series_need_eligibility_evidence() {
        let restriction = TransferRestriction::QualifiedHolders {
            eligibility_policy_digest: id(37),
        };
        let mut book = DistributionBook::default();
        assert_eq!(
            book.admit(
                request(Venue::Oclob, None),
                &series(restriction.clone()),
                60
            ),
            Err(DistributionError::EligibilityRequired)
        );
        let mut qualified = request(Venue::Oclob, None);
        qualified.eligibility_attestation_digest = Some(id(77));
        book.admit(qualified, &series(restriction), 60).unwrap();
    }

    #[test]
    fn fills_are_bounded_by_the_request_and_each_gets_its_own_nullifier() {
        let mut book = DistributionBook::default();
        let handoff = book
            .admit(
                request(Venue::Qomm, None),
                &series(TransferRestriction::Unrestricted),
                60,
            )
            .unwrap();
        assert_eq!(handoff.venue, Venue::Qomm);
        let first = book.accept_fill(fill(1, 30, 201), 100).unwrap();
        assert_eq!(
            book.accept_fill(fill(2, 21, 202), 100),
            Err(DistributionError::OverFilled)
        );
        let second = book.accept_fill(fill(2, 20, 202), 100).unwrap();
        assert_ne!(first.nullifier, second.nullifier);
        assert_eq!(first.seller_commitment, id(200));
        assert_eq!(first.buyer_commitment, id(201));
        assert_eq!(first.deadline, 500);
        assert_eq!(
            book.accept_fill(fill(1, 1, 201), 100),
            Err(DistributionError::OverFilled)
        );
        let mut self_dealing = fill(3, 1, 200);
        self_dealing.units = 0;
        assert_eq!(
            book.accept_fill(self_dealing, 100),
            Err(DistributionError::InvalidFill)
        );
        assert!(book.validate().is_ok());
        assert!(book.root().is_ok());
    }

    #[test]
    fn a_bilateral_fill_must_name_the_agreed_counterparty() {
        let mut book = DistributionBook::default();
        book.admit(
            request(Venue::Bilateral, Some(id(201))),
            &series(TransferRestriction::Unrestricted),
            60,
        )
        .unwrap();
        let mut wrong = fill(1, 50, 202);
        wrong.venue = Venue::Bilateral;
        assert_eq!(
            book.accept_fill(wrong, 100),
            Err(DistributionError::FillMismatch)
        );
        let mut wrong_venue = fill(1, 50, 201);
        wrong_venue.venue = Venue::Qomm;
        assert_eq!(
            book.accept_fill(wrong_venue, 100),
            Err(DistributionError::FillMismatch)
        );
    }

    #[test]
    fn outcomes_respect_the_deadline_and_release_unsettled_units() {
        let mut book = DistributionBook::default();
        book.admit(
            request(Venue::Qomm, None),
            &series(TransferRestriction::Unrestricted),
            60,
        )
        .unwrap();
        let context = book.accept_fill(fill(1, 50, 201), 100).unwrap();
        assert_eq!(
            book.record_outcome(
                &context.context_id,
                SettlementOutcome::Settled {
                    receipt_digest: id(9),
                    finalized_at: 501,
                }
            ),
            Err(DistributionError::InvalidOutcome)
        );
        assert_eq!(
            book.record_outcome(&context.context_id, SettlementOutcome::Expired { at: 400 }),
            Err(DistributionError::InvalidOutcome)
        );
        book.record_outcome(
            &context.context_id,
            SettlementOutcome::Rejected {
                reason_digest: id(8),
                at: 120,
            },
        )
        .unwrap();
        assert_eq!(book.request(&id(70)).unwrap().filled_units, 0);
        let again = book.accept_fill(fill(2, 50, 203), 130).unwrap();
        book.record_outcome(
            &again.context_id,
            SettlementOutcome::Settled {
                receipt_digest: id(9),
                finalized_at: 140,
            },
        )
        .unwrap();
        assert_eq!(
            book.record_outcome(&again.context_id, SettlementOutcome::Expired { at: 600 }),
            Err(DistributionError::Replay)
        );
        assert!(book.validate().is_ok());
    }

    #[test]
    fn requests_expire_and_a_frozen_series_admits_nothing() {
        let mut book = DistributionBook::default();
        assert_eq!(
            book.admit(
                request(Venue::Qomm, None),
                &series(TransferRestriction::Unrestricted),
                501
            ),
            Err(DistributionError::OutsideValidityWindow)
        );
        let mut frozen = series(TransferRestriction::Unrestricted);
        frozen.status = TokenSeriesStatus::Frozen;
        assert_eq!(
            book.admit(request(Venue::Qomm, None), &frozen, 60),
            Err(DistributionError::SeriesUnavailable)
        );
        book.admit(
            request(Venue::Qomm, None),
            &series(TransferRestriction::Unrestricted),
            60,
        )
        .unwrap();
        assert_eq!(
            book.accept_fill(fill(1, 10, 201), 501),
            Err(DistributionError::OutsideValidityWindow)
        );
    }
}
