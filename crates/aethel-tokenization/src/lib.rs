//! Receivable tokenization: what a token of an Aethel receivable is, how much
//! of it may exist, and what an external asset ledger is asked to do.
//!
//! A [`TokenSeries`] binds one Aethel receivable series to one DeFMI asset
//! and fixes the unit of the token (whole receivable or fractions), the
//! optional tranches, the issuance cap, the transfer restriction, and the
//! conditions under which units are redeemed. An [`IssuanceAuthorization`]
//! opens the unit count a host proved for one `ReceivableIssuance`; every
//! [`SupplyIntent`] (mint or burn) names that issuance and its series, and
//! supply accounting refuses a mint beyond the authorization or a burn beyond
//! what was minted.
//!
//! This crate holds no balances. Who owns how many units is DeFMI's ledger;
//! the crate emits validated intents through [`AssetLedgerPort`] and records
//! the receipts the ledger returns. Its [`TokenizationBook`] stores series,
//! authorizations, per-issuance supply counters, and intents, and nothing
//! keyed by a holder.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use aethel_core::{LossLayer, ReceivableIssuance, ReceivableSeries};
use aethel_types::{
    digest, id_key, valid_time, valid_window, Commitment, EncodingError, Identifier, ZERO,
};

const TOKEN_SERIES_DOMAIN: &[u8] = b"AETHEL:TOKEN-SERIES:v1";
const ISSUANCE_AUTHORIZATION_DOMAIN: &[u8] = b"AETHEL:ISSUANCE-AUTHORIZATION:v1";
const SUPPLY_INTENT_DOMAIN: &[u8] = b"AETHEL:SUPPLY-INTENT:v1";
const TOKENIZATION_BOOK_DOMAIN: &[u8] = b"AETHEL:TOKENIZATION-BOOK:v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenSeriesStatus {
    /// Authorizations, mints, and burns are accepted.
    Open,
    /// No new authorization or mint; burns still settle outstanding units.
    Frozen,
    /// Every unit has been burned; terminal.
    Redeemed,
}

/// Who may take a unit from its current holder. The restriction is evaluated
/// by the distribution boundary; the ledger enforces the resulting lock.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TransferRestriction {
    NonTransferable,
    IssuerRepurchaseOnly {
        issuer_commitment: Commitment,
    },
    QualifiedHolders {
        eligibility_policy_digest: Commitment,
    },
    Unrestricted,
}

impl TransferRestriction {
    fn validate(&self) -> Result<(), TokenizationError> {
        match self {
            Self::IssuerRepurchaseOnly { issuer_commitment } if *issuer_commitment == ZERO => {
                Err(TokenizationError::InvalidTokenSeries)
            }
            Self::QualifiedHolders {
                eligibility_policy_digest,
            } if *eligibility_policy_digest == ZERO => Err(TokenizationError::InvalidTokenSeries),
            _ => Ok(()),
        }
    }

    /// Whether a holder other than the issuer may ever receive a unit.
    pub fn permits_secondary_transfer(&self) -> bool {
        matches!(self, Self::QualifiedHolders { .. } | Self::Unrestricted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedemptionCondition {
    /// The stream closed with the receivable paid: units redeem for cash.
    StreamClosed,
    /// A guarantee claim settled: units redeem against the recovery.
    GuaranteeClaimSettled,
    /// The series reached maturity.
    Maturity,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BurnReason {
    Redemption,
    GuaranteeClaim,
    /// The issuer withdraws units it still holds before any transfer.
    Cancellation,
}

/// One loss-layer class of a series. Tranche caps partition the issuance cap.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Tranche {
    pub tranche_id: Identifier,
    pub loss_layer: LossLayer,
    pub unit_cap: u64,
}

/// The token definition of one Aethel receivable series.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TokenSeries {
    pub token_series_id: Identifier,
    /// The Aethel `ReceivableSeries` this tokenizes.
    pub series_id: Identifier,
    /// The DeFMI asset the series' notes and these units live under.
    pub receivable_asset_id: Identifier,
    pub aethel_domain_id: Identifier,
    pub issuer_participant_id: Identifier,
    /// Units per whole receivable: 1 for an indivisible token.
    pub units_per_receivable: u64,
    /// Total units that may ever be authorized across the series' issuances.
    pub issuance_cap_units: u64,
    /// Empty for a single class; otherwise the caps sum to the issuance cap.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tranches: Vec<Tranche>,
    pub transfer_restriction: TransferRestriction,
    pub redemption: Vec<RedemptionCondition>,
    pub valid_from: u64,
    pub maturity: u64,
    pub status: TokenSeriesStatus,
}

impl TokenSeries {
    pub fn validate_initial(&self) -> Result<(), TokenizationError> {
        if [
            self.token_series_id,
            self.series_id,
            self.receivable_asset_id,
            self.aethel_domain_id,
            self.issuer_participant_id,
        ]
        .contains(&ZERO)
            || self.units_per_receivable == 0
            || self.issuance_cap_units == 0
            || self.redemption.is_empty()
            || !valid_window(self.valid_from, self.maturity)
            || self.status != TokenSeriesStatus::Open
        {
            return Err(TokenizationError::InvalidTokenSeries);
        }
        self.transfer_restriction.validate()?;
        let conditions = self.redemption.iter().collect::<BTreeSet<_>>();
        if conditions.len() != self.redemption.len() {
            return Err(TokenizationError::InvalidTokenSeries);
        }
        let mut ids = BTreeSet::new();
        let mut total: u64 = 0;
        for tranche in &self.tranches {
            if tranche.tranche_id == ZERO
                || tranche.unit_cap == 0
                || !ids.insert(tranche.tranche_id)
            {
                return Err(TokenizationError::InvalidTokenSeries);
            }
            total = total
                .checked_add(tranche.unit_cap)
                .ok_or(TokenizationError::ArithmeticOverflow)?;
        }
        if !self.tranches.is_empty() && total != self.issuance_cap_units {
            return Err(TokenizationError::InvalidTokenSeries);
        }
        Ok(())
    }

    /// The token series must describe exactly the Aethel series it names, and
    /// must not promise more transferability than the series policy allows.
    pub fn bound_to(&self, series: &ReceivableSeries) -> Result<(), TokenizationError> {
        if series.series_id != self.series_id
            || series.receivable_asset_id != self.receivable_asset_id
            || series.aethel_domain_id != self.aethel_domain_id
            || series.issuer_participant_id != self.issuer_participant_id
            || series.maturity != self.maturity
            || (!series.policy.allow_secondary_transfer
                && self.transfer_restriction.permits_secondary_transfer())
        {
            return Err(TokenizationError::SeriesMismatch);
        }
        Ok(())
    }

    pub fn tranche(&self, tranche_id: &Identifier) -> Option<&Tranche> {
        self.tranches
            .iter()
            .find(|tranche| tranche.tranche_id == *tranche_id)
    }

    fn permits_burn(&self, reason: BurnReason) -> bool {
        match reason {
            BurnReason::Cancellation => true,
            BurnReason::Redemption => self.redemption.iter().any(|condition| {
                matches!(
                    condition,
                    RedemptionCondition::StreamClosed | RedemptionCondition::Maturity
                )
            }),
            BurnReason::GuaranteeClaim => self
                .redemption
                .contains(&RedemptionCondition::GuaranteeClaimSettled),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegisterTokenSeries {
    pub operation_id: Identifier,
    pub token_series: TokenSeries,
}

impl RegisterTokenSeries {
    pub fn statement(&self) -> Result<Commitment, TokenizationError> {
        if self.operation_id == ZERO {
            return Err(TokenizationError::InvalidTokenSeries);
        }
        self.token_series.validate_initial()?;
        Ok(digest(TOKEN_SERIES_DOMAIN, self)?)
    }
}

/// The unit count a host opened for one Aethel issuance. The host verified
/// the issuance zkPI, which relates the committed face value to these units;
/// `authorization_digest` is that zkPI digest, so the authorization cannot be
/// detached from the issuance that proved it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssuanceAuthorization {
    pub operation_id: Identifier,
    pub issuance_id: Identifier,
    pub token_series_id: Identifier,
    pub series_id: Identifier,
    pub note_id: Identifier,
    pub face_value_commitment: Commitment,
    pub authorized_units: u64,
    pub authorization_digest: Commitment,
    pub authorized_at: u64,
}

impl IssuanceAuthorization {
    pub fn statement(&self) -> Result<Commitment, TokenizationError> {
        if [
            self.operation_id,
            self.issuance_id,
            self.token_series_id,
            self.series_id,
            self.note_id,
            self.face_value_commitment,
            self.authorization_digest,
        ]
        .contains(&ZERO)
            || self.authorized_units == 0
            || !valid_time(self.authorized_at)
        {
            return Err(TokenizationError::InvalidAuthorization);
        }
        Ok(digest(ISSUANCE_AUTHORIZATION_DOMAIN, self)?)
    }

    /// The authorization must name exactly the Aethel issuance it opens.
    pub fn bound_to(&self, issuance: &ReceivableIssuance) -> Result<(), TokenizationError> {
        if issuance.issuance_id != self.issuance_id
            || issuance.series_id != self.series_id
            || issuance.note_id != self.note_id
            || issuance.face_value_commitment != self.face_value_commitment
            || issuance.zkpi_digest != self.authorization_digest
        {
            return Err(TokenizationError::IssuanceMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SupplyChange {
    Mint {
        units: u64,
        recipient_commitment: Commitment,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tranche_id: Option<Identifier>,
    },
    Burn {
        units: u64,
        holder_commitment: Commitment,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tranche_id: Option<Identifier>,
        reason: BurnReason,
    },
}

impl SupplyChange {
    pub fn units(&self) -> u64 {
        match self {
            Self::Mint { units, .. } | Self::Burn { units, .. } => *units,
        }
    }

    fn tranche_id(&self) -> Option<Identifier> {
        match self {
            Self::Mint { tranche_id, .. } | Self::Burn { tranche_id, .. } => *tranche_id,
        }
    }

    fn subject(&self) -> Commitment {
        match self {
            Self::Mint {
                recipient_commitment,
                ..
            } => *recipient_commitment,
            Self::Burn {
                holder_commitment, ..
            } => *holder_commitment,
        }
    }
}

/// A validated command to the external asset ledger. Every intent names the
/// series and the issuance whose authorization it draws on.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SupplyIntent {
    pub intent_id: Identifier,
    pub operation_id: Identifier,
    pub token_series_id: Identifier,
    pub series_id: Identifier,
    pub issuance_id: Identifier,
    pub receivable_asset_id: Identifier,
    pub change: SupplyChange,
    pub authorization_digest: Commitment,
    pub created_at: u64,
}

impl SupplyIntent {
    pub fn statement(&self) -> Result<Commitment, TokenizationError> {
        if [
            self.intent_id,
            self.operation_id,
            self.token_series_id,
            self.series_id,
            self.issuance_id,
            self.receivable_asset_id,
            self.authorization_digest,
            self.change.subject(),
        ]
        .contains(&ZERO)
            || self.change.tranche_id() == Some(ZERO)
            || self.change.units() == 0
            || !valid_time(self.created_at)
        {
            return Err(TokenizationError::InvalidIntent);
        }
        Ok(digest(SUPPLY_INTENT_DOMAIN, self)?)
    }
}

/// What the ledger returns for an applied intent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SupplyReceipt {
    pub intent_id: Identifier,
    pub receipt_digest: Commitment,
    pub ledger_sequence: u64,
    pub finalized_at: u64,
}

/// The ledger refused an intent. The reason is the ledger's; this crate only
/// records that the units were not created or destroyed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LedgerRejection {
    pub reason_digest: Commitment,
    pub rejected_at: u64,
}

/// The boundary to the authoritative asset ledger (DeFMI). The implementation
/// owns balances and ownership; this crate never reads them back.
pub trait AssetLedgerPort {
    fn apply_supply_intent(
        &mut self,
        intent: &SupplyIntent,
    ) -> Result<SupplyReceipt, LedgerRejection>;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum IntentStatus {
    Pending,
    Applied { receipt: SupplyReceipt },
    Rejected { rejection: LedgerRejection },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedIntent {
    pub intent: SupplyIntent,
    pub status: IntentStatus,
}

/// Supply accounting for one issuance: the cap and the units that have been
/// or are being created against it. No holder appears here.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SupplyAccount {
    pub authorized_units: u64,
    pub pending_mint: u64,
    pub minted: u64,
    pub pending_burn: u64,
    pub burned: u64,
}

impl SupplyAccount {
    /// Units that exist on the ledger.
    pub fn outstanding(&self) -> u64 {
        self.minted - self.burned
    }

    fn committed_mint(&self) -> u64 {
        self.pending_mint + self.minted
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TokenizationBook {
    pub token_series: BTreeMap<String, TokenSeries>,
    pub authorizations: BTreeMap<String, IssuanceAuthorization>,
    /// Keyed by issuance id.
    pub accounts: BTreeMap<String, SupplyAccount>,
    pub intents: BTreeMap<String, RecordedIntent>,
    pub used_operations: BTreeSet<String>,
}

/// A request to create units against one issuance authorization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintRequest {
    pub operation_id: Identifier,
    pub intent_id: Identifier,
    pub issuance_id: Identifier,
    pub units: u64,
    pub recipient_commitment: Commitment,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tranche_id: Option<Identifier>,
}

/// A request to destroy units of one issuance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BurnRequest {
    pub operation_id: Identifier,
    pub intent_id: Identifier,
    pub issuance_id: Identifier,
    pub units: u64,
    pub holder_commitment: Commitment,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tranche_id: Option<Identifier>,
    pub reason: BurnReason,
}

impl TokenizationBook {
    pub fn root(&self) -> Result<Commitment, TokenizationError> {
        self.validate()?;
        Ok(digest(TOKENIZATION_BOOK_DOMAIN, self)?)
    }

    pub fn token_series(
        &self,
        token_series_id: &Identifier,
    ) -> Result<&TokenSeries, TokenizationError> {
        self.token_series
            .get(&id_key(token_series_id))
            .ok_or(TokenizationError::UnknownTokenSeries)
    }

    pub fn authorization(
        &self,
        issuance_id: &Identifier,
    ) -> Result<&IssuanceAuthorization, TokenizationError> {
        self.authorizations
            .get(&id_key(issuance_id))
            .ok_or(TokenizationError::UnknownAuthorization)
    }

    pub fn account(&self, issuance_id: &Identifier) -> Result<&SupplyAccount, TokenizationError> {
        self.accounts
            .get(&id_key(issuance_id))
            .ok_or(TokenizationError::UnknownAuthorization)
    }

    pub fn intent(&self, intent_id: &Identifier) -> Result<&RecordedIntent, TokenizationError> {
        self.intents
            .get(&id_key(intent_id))
            .ok_or(TokenizationError::UnknownIntent)
    }

    /// Units of one series that exist on the ledger, summed over issuances.
    pub fn outstanding_units(&self, token_series_id: &Identifier) -> u64 {
        self.authorizations
            .values()
            .filter(|authorization| authorization.token_series_id == *token_series_id)
            .filter_map(|authorization| self.accounts.get(&id_key(&authorization.issuance_id)))
            .map(SupplyAccount::outstanding)
            .sum()
    }

    /// Registers the token definition of `series`, which the caller took from
    /// the authoritative Aethel book.
    pub fn register_token_series(
        &mut self,
        request: RegisterTokenSeries,
        series: &ReceivableSeries,
        now: u64,
    ) -> Result<Commitment, TokenizationError> {
        let statement = request.statement()?;
        request.token_series.bound_to(series)?;
        if now < request.token_series.valid_from || now > request.token_series.maturity {
            return Err(TokenizationError::OutsideValidityWindow);
        }
        let key = id_key(&request.token_series.token_series_id);
        if self.token_series.contains_key(&key)
            || self
                .token_series
                .values()
                .any(|existing| existing.series_id == request.token_series.series_id)
        {
            return Err(TokenizationError::DuplicateTokenSeries);
        }
        self.consume_operation(&request.operation_id)?;
        self.token_series.insert(key, request.token_series);
        Ok(statement)
    }

    /// Opens the unit count of one Aethel issuance. `issuance` is the record
    /// the authoritative Aethel book accepted; the authorization must describe
    /// it exactly and must fit under the series cap.
    pub fn authorize_issuance(
        &mut self,
        authorization: IssuanceAuthorization,
        issuance: &ReceivableIssuance,
        now: u64,
    ) -> Result<Commitment, TokenizationError> {
        let statement = authorization.statement()?;
        authorization.bound_to(issuance)?;
        if authorization.authorized_at != now {
            return Err(TokenizationError::OutsideValidityWindow);
        }
        let series = self.token_series(&authorization.token_series_id)?;
        if series.series_id != authorization.series_id {
            return Err(TokenizationError::SeriesMismatch);
        }
        if series.status != TokenSeriesStatus::Open || now > series.maturity {
            return Err(TokenizationError::TokenSeriesUnavailable);
        }
        let key = id_key(&authorization.issuance_id);
        if self.authorizations.contains_key(&key)
            || self
                .authorizations
                .values()
                .any(|existing| existing.note_id == authorization.note_id)
        {
            return Err(TokenizationError::DuplicateAuthorization);
        }
        let already_authorized = self
            .authorizations
            .values()
            .filter(|existing| existing.token_series_id == authorization.token_series_id)
            .try_fold(0u64, |total, existing| {
                total.checked_add(existing.authorized_units)
            })
            .ok_or(TokenizationError::ArithmeticOverflow)?;
        if already_authorized
            .checked_add(authorization.authorized_units)
            .ok_or(TokenizationError::ArithmeticOverflow)?
            > series.issuance_cap_units
        {
            return Err(TokenizationError::SupplyExceedsAuthorization);
        }
        self.consume_operation(&authorization.operation_id)?;
        self.accounts.insert(
            key.clone(),
            SupplyAccount {
                authorized_units: authorization.authorized_units,
                ..SupplyAccount::default()
            },
        );
        self.authorizations.insert(key, authorization);
        Ok(statement)
    }

    /// Prepares a mint intent. Pending and applied mints together never
    /// exceed the issuance authorization or the tranche cap.
    pub fn mint(
        &mut self,
        request: MintRequest,
        now: u64,
    ) -> Result<SupplyIntent, TokenizationError> {
        let authorization = self.authorization(&request.issuance_id)?.clone();
        let series = self.token_series(&authorization.token_series_id)?.clone();
        if series.status != TokenSeriesStatus::Open || now > series.maturity {
            return Err(TokenizationError::TokenSeriesUnavailable);
        }
        self.check_tranche(&series, request.tranche_id)?;
        let account = self.account(&request.issuance_id)?;
        if account
            .committed_mint()
            .checked_add(request.units)
            .ok_or(TokenizationError::ArithmeticOverflow)?
            > account.authorized_units
        {
            return Err(TokenizationError::SupplyExceedsAuthorization);
        }
        if let Some(tranche_id) = request.tranche_id {
            let cap = series
                .tranche(&tranche_id)
                .map(|tranche| tranche.unit_cap)
                .ok_or(TokenizationError::UnknownTranche)?;
            if self
                .tranche_committed_mint(&series.token_series_id, &tranche_id)
                .checked_add(request.units)
                .ok_or(TokenizationError::ArithmeticOverflow)?
                > cap
            {
                return Err(TokenizationError::SupplyExceedsAuthorization);
            }
        }
        let intent = SupplyIntent {
            intent_id: request.intent_id,
            operation_id: request.operation_id,
            token_series_id: series.token_series_id,
            series_id: series.series_id,
            issuance_id: request.issuance_id,
            receivable_asset_id: series.receivable_asset_id,
            change: SupplyChange::Mint {
                units: request.units,
                recipient_commitment: request.recipient_commitment,
                tranche_id: request.tranche_id,
            },
            authorization_digest: authorization.authorization_digest,
            created_at: now,
        };
        self.record_intent(intent.clone())?;
        self.accounts
            .get_mut(&id_key(&request.issuance_id))
            .expect("checked account")
            .pending_mint += request.units;
        Ok(intent)
    }

    /// Prepares a burn intent. Units burned never exceed units minted, and the
    /// reason must be one the series' redemption conditions allow.
    pub fn burn(
        &mut self,
        request: BurnRequest,
        now: u64,
    ) -> Result<SupplyIntent, TokenizationError> {
        let authorization = self.authorization(&request.issuance_id)?.clone();
        let series = self.token_series(&authorization.token_series_id)?.clone();
        if series.status == TokenSeriesStatus::Redeemed {
            return Err(TokenizationError::TokenSeriesUnavailable);
        }
        if !series.permits_burn(request.reason) {
            return Err(TokenizationError::RedemptionNotPermitted);
        }
        self.check_tranche(&series, request.tranche_id)?;
        let account = self.account(&request.issuance_id)?;
        if account.pending_burn + request.units > account.minted - account.burned {
            return Err(TokenizationError::BurnExceedsSupply);
        }
        let intent = SupplyIntent {
            intent_id: request.intent_id,
            operation_id: request.operation_id,
            token_series_id: series.token_series_id,
            series_id: series.series_id,
            issuance_id: request.issuance_id,
            receivable_asset_id: series.receivable_asset_id,
            change: SupplyChange::Burn {
                units: request.units,
                holder_commitment: request.holder_commitment,
                tranche_id: request.tranche_id,
                reason: request.reason,
            },
            authorization_digest: authorization.authorization_digest,
            created_at: now,
        };
        self.record_intent(intent.clone())?;
        self.accounts
            .get_mut(&id_key(&request.issuance_id))
            .expect("checked account")
            .pending_burn += request.units;
        Ok(intent)
    }

    /// Hands a pending intent to the ledger and records what it returned.
    /// Re-submitting an applied intent returns its receipt without touching
    /// the ledger again; a rejected intent releases the units it held.
    pub fn submit<P: AssetLedgerPort>(
        &mut self,
        intent_id: &Identifier,
        ledger: &mut P,
    ) -> Result<SupplyReceipt, TokenizationError> {
        let key = id_key(intent_id);
        let recorded = self
            .intents
            .get(&key)
            .ok_or(TokenizationError::UnknownIntent)?
            .clone();
        match recorded.status {
            IntentStatus::Applied { receipt } => return Ok(receipt),
            IntentStatus::Rejected { .. } => return Err(TokenizationError::IntentRejected),
            IntentStatus::Pending => {}
        }
        let units = recorded.intent.change.units();
        let account_key = id_key(&recorded.intent.issuance_id);
        match ledger.apply_supply_intent(&recorded.intent) {
            Ok(receipt) => {
                if receipt.intent_id != *intent_id
                    || receipt.receipt_digest == ZERO
                    || !valid_time(receipt.finalized_at)
                {
                    return Err(TokenizationError::InvalidReceipt);
                }
                let account = self
                    .accounts
                    .get_mut(&account_key)
                    .expect("recorded account");
                match recorded.intent.change {
                    SupplyChange::Mint { .. } => {
                        account.pending_mint -= units;
                        account.minted += units;
                    }
                    SupplyChange::Burn { .. } => {
                        account.pending_burn -= units;
                        account.burned += units;
                    }
                }
                self.intents.get_mut(&key).expect("recorded intent").status =
                    IntentStatus::Applied {
                        receipt: receipt.clone(),
                    };
                Ok(receipt)
            }
            Err(rejection) => {
                let account = self
                    .accounts
                    .get_mut(&account_key)
                    .expect("recorded account");
                match recorded.intent.change {
                    SupplyChange::Mint { .. } => account.pending_mint -= units,
                    SupplyChange::Burn { .. } => account.pending_burn -= units,
                }
                self.intents.get_mut(&key).expect("recorded intent").status =
                    IntentStatus::Rejected { rejection };
                Err(TokenizationError::IntentRejected)
            }
        }
    }

    /// Freezes an open series, reopens a frozen one, or closes a series whose
    /// units are all burned.
    pub fn set_status(
        &mut self,
        operation_id: Identifier,
        token_series_id: &Identifier,
        status: TokenSeriesStatus,
    ) -> Result<(), TokenizationError> {
        self.ensure_operation_unused(&operation_id)?;
        let outstanding = self.outstanding_units(token_series_id);
        let series = self.token_series(token_series_id)?;
        let allowed = match (series.status, status) {
            (TokenSeriesStatus::Open, TokenSeriesStatus::Frozen)
            | (TokenSeriesStatus::Frozen, TokenSeriesStatus::Open) => true,
            (TokenSeriesStatus::Open | TokenSeriesStatus::Frozen, TokenSeriesStatus::Redeemed) => {
                outstanding == 0 && self.pending_units(token_series_id) == 0
            }
            _ => false,
        };
        if !allowed {
            return Err(TokenizationError::TokenSeriesUnavailable);
        }
        self.consume_operation(&operation_id)?;
        self.token_series
            .get_mut(&id_key(token_series_id))
            .expect("checked series")
            .status = status;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), TokenizationError> {
        for (key, series) in &self.token_series {
            let mut initial = series.clone();
            initial.status = TokenSeriesStatus::Open;
            initial.validate_initial()?;
            if key != &id_key(&series.token_series_id) {
                return Err(TokenizationError::InvalidState);
            }
        }
        let mut authorized_by_series: BTreeMap<Identifier, u64> = BTreeMap::new();
        for (key, authorization) in &self.authorizations {
            authorization.statement()?;
            let series = self.token_series(&authorization.token_series_id)?;
            if key != &id_key(&authorization.issuance_id)
                || series.series_id != authorization.series_id
                || !self.accounts.contains_key(key)
            {
                return Err(TokenizationError::InvalidState);
            }
            let total = authorized_by_series
                .entry(authorization.token_series_id)
                .or_default();
            *total = total
                .checked_add(authorization.authorized_units)
                .ok_or(TokenizationError::ArithmeticOverflow)?;
            if *total > series.issuance_cap_units {
                return Err(TokenizationError::InvalidState);
            }
        }
        let mut expected: BTreeMap<String, SupplyAccount> = self
            .authorizations
            .iter()
            .map(|(key, authorization)| {
                (
                    key.clone(),
                    SupplyAccount {
                        authorized_units: authorization.authorized_units,
                        ..SupplyAccount::default()
                    },
                )
            })
            .collect();
        for (key, recorded) in &self.intents {
            recorded.intent.statement()?;
            let authorization = self.authorization(&recorded.intent.issuance_id)?;
            let series = self.token_series(&recorded.intent.token_series_id)?;
            if key != &id_key(&recorded.intent.intent_id)
                || authorization.token_series_id != recorded.intent.token_series_id
                || authorization.authorization_digest != recorded.intent.authorization_digest
                || series.series_id != recorded.intent.series_id
                || series.receivable_asset_id != recorded.intent.receivable_asset_id
                || !self
                    .used_operations
                    .contains(&id_key(&recorded.intent.operation_id))
            {
                return Err(TokenizationError::InvalidState);
            }
            let account = expected
                .get_mut(&id_key(&recorded.intent.issuance_id))
                .ok_or(TokenizationError::InvalidState)?;
            let units = recorded.intent.change.units();
            match (&recorded.intent.change, &recorded.status) {
                (SupplyChange::Mint { .. }, IntentStatus::Pending) => account.pending_mint += units,
                (SupplyChange::Mint { .. }, IntentStatus::Applied { .. }) => {
                    account.minted += units
                }
                (SupplyChange::Burn { .. }, IntentStatus::Pending) => account.pending_burn += units,
                (SupplyChange::Burn { .. }, IntentStatus::Applied { .. }) => {
                    account.burned += units
                }
                (_, IntentStatus::Rejected { .. }) => {}
            }
        }
        for (key, account) in &expected {
            if self.accounts.get(key) != Some(account)
                || account.committed_mint() > account.authorized_units
                || account.burned + account.pending_burn > account.minted
            {
                return Err(TokenizationError::InvalidState);
            }
        }
        if self.accounts.len() != expected.len() {
            return Err(TokenizationError::InvalidState);
        }
        Ok(())
    }

    fn check_tranche(
        &self,
        series: &TokenSeries,
        tranche_id: Option<Identifier>,
    ) -> Result<(), TokenizationError> {
        match (series.tranches.is_empty(), tranche_id) {
            (true, None) => Ok(()),
            (true, Some(_)) | (false, None) => Err(TokenizationError::UnknownTranche),
            (false, Some(id)) => series
                .tranche(&id)
                .map(|_| ())
                .ok_or(TokenizationError::UnknownTranche),
        }
    }

    fn tranche_committed_mint(&self, token_series_id: &Identifier, tranche_id: &Identifier) -> u64 {
        self.intents
            .values()
            .filter(|recorded| {
                recorded.intent.token_series_id == *token_series_id
                    && !matches!(recorded.status, IntentStatus::Rejected { .. })
            })
            .filter_map(|recorded| match &recorded.intent.change {
                SupplyChange::Mint {
                    units,
                    tranche_id: Some(id),
                    ..
                } if id == tranche_id => Some(*units),
                _ => None,
            })
            .sum()
    }

    fn pending_units(&self, token_series_id: &Identifier) -> u64 {
        self.authorizations
            .values()
            .filter(|authorization| authorization.token_series_id == *token_series_id)
            .filter_map(|authorization| self.accounts.get(&id_key(&authorization.issuance_id)))
            .map(|account| account.pending_mint + account.pending_burn)
            .sum()
    }

    fn record_intent(&mut self, intent: SupplyIntent) -> Result<(), TokenizationError> {
        intent.statement()?;
        let key = id_key(&intent.intent_id);
        if self.intents.contains_key(&key) {
            return Err(TokenizationError::Replay);
        }
        self.consume_operation(&intent.operation_id)?;
        self.intents.insert(
            key,
            RecordedIntent {
                intent,
                status: IntentStatus::Pending,
            },
        );
        Ok(())
    }

    fn ensure_operation_unused(&self, operation_id: &Identifier) -> Result<(), TokenizationError> {
        if *operation_id == ZERO || self.used_operations.contains(&id_key(operation_id)) {
            return Err(TokenizationError::Replay);
        }
        Ok(())
    }

    fn consume_operation(&mut self, operation_id: &Identifier) -> Result<(), TokenizationError> {
        self.ensure_operation_unused(operation_id)?;
        self.used_operations.insert(id_key(operation_id));
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TokenizationError {
    #[error("tokenization record encoding failed")]
    Encoding,
    #[error("tokenization state is invalid")]
    InvalidState,
    #[error("token series is invalid")]
    InvalidTokenSeries,
    #[error("token series is unknown")]
    UnknownTokenSeries,
    #[error("token series already exists for this receivable series")]
    DuplicateTokenSeries,
    #[error("token series is frozen, redeemed, or past maturity")]
    TokenSeriesUnavailable,
    #[error("token series does not describe the Aethel receivable series")]
    SeriesMismatch,
    #[error("issuance authorization is invalid")]
    InvalidAuthorization,
    #[error("issuance authorization does not describe the Aethel issuance")]
    IssuanceMismatch,
    #[error("issuance authorization is unknown")]
    UnknownAuthorization,
    #[error("issuance or note is already authorized")]
    DuplicateAuthorization,
    #[error("supply would exceed the bound receivable authorization")]
    SupplyExceedsAuthorization,
    #[error("burn would exceed the units minted")]
    BurnExceedsSupply,
    #[error("series redemption conditions do not permit this burn")]
    RedemptionNotPermitted,
    #[error("tranche is unknown for this series")]
    UnknownTranche,
    #[error("supply intent is invalid")]
    InvalidIntent,
    #[error("supply intent is unknown")]
    UnknownIntent,
    #[error("ledger rejected the supply intent")]
    IntentRejected,
    #[error("ledger receipt does not describe the intent")]
    InvalidReceipt,
    #[error("artifact is outside its validity window")]
    OutsideValidityWindow,
    #[error("operation or intent was already used")]
    Replay,
    #[error("arithmetic overflow")]
    ArithmeticOverflow,
}

impl From<EncodingError> for TokenizationError {
    fn from(_: EncodingError) -> Self {
        Self::Encoding
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aethel_core::dekyx_core::SubjectKind;
    use aethel_core::{ReceivableStatus, SeriesPolicy};

    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn series(allow_secondary_transfer: bool) -> ReceivableSeries {
        ReceivableSeries {
            series_id: id(34),
            aethel_domain_id: id(39),
            stream_id: id(20),
            receivable_asset_id: id(35),
            issuer_participant_id: id(36),
            policy: SeriesPolicy {
                requires_credit_decision: false,
                requires_guarantee: false,
                requires_funding_reservation: false,
                requires_confidential_subject: false,
                subject_kind: SubjectKind::LegalEntity,
                required_qualifications: Vec::new(),
                accepted_issuer_namespace_digest: None,
                allow_secondary_transfer,
                eligibility_policy_digest: id(37),
                claim_policy_digest: id(38),
            },
            valid_from: 1,
            maturity: 1_000,
            sequence: 0,
            status: ReceivableStatus::Active,
        }
    }

    fn token_series(restriction: TransferRestriction, tranches: Vec<Tranche>) -> TokenSeries {
        TokenSeries {
            token_series_id: id(60),
            series_id: id(34),
            receivable_asset_id: id(35),
            aethel_domain_id: id(39),
            issuer_participant_id: id(36),
            units_per_receivable: 100,
            issuance_cap_units: 1_000,
            tranches,
            transfer_restriction: restriction,
            redemption: vec![RedemptionCondition::StreamClosed],
            valid_from: 1,
            maturity: 1_000,
            status: TokenSeriesStatus::Open,
        }
    }

    fn issuance() -> ReceivableIssuance {
        ReceivableIssuance {
            operation_id: id(90),
            issuance_id: id(91),
            request_id: id(50),
            series_id: id(34),
            note_id: id(92),
            owner_commitment: id(93),
            face_value_commitment: id(94),
            before_stream_state_version: 1,
            before_stream_state_root: id(95),
            after_pledged_commitment: id(96),
            allocation_nullifier: id(97),
            credit_decision_id: None,
            guarantee_id: None,
            funding_quote_id: None,
            relation_proof_digest: id(98),
            zkpi_digest: id(99),
            issued_at: 50,
        }
    }

    fn authorization(units: u64) -> IssuanceAuthorization {
        IssuanceAuthorization {
            operation_id: id(70),
            issuance_id: id(91),
            token_series_id: id(60),
            series_id: id(34),
            note_id: id(92),
            face_value_commitment: id(94),
            authorized_units: units,
            authorization_digest: id(99),
            authorized_at: 50,
        }
    }

    struct Ledger {
        sequence: u64,
        reject: bool,
    }

    impl AssetLedgerPort for Ledger {
        fn apply_supply_intent(
            &mut self,
            intent: &SupplyIntent,
        ) -> Result<SupplyReceipt, LedgerRejection> {
            if self.reject {
                return Err(LedgerRejection {
                    reason_digest: id(1),
                    rejected_at: 60,
                });
            }
            self.sequence += 1;
            Ok(SupplyReceipt {
                intent_id: intent.intent_id,
                receipt_digest: intent.statement().unwrap(),
                ledger_sequence: self.sequence,
                finalized_at: 60,
            })
        }
    }

    fn book_with_authorization(units: u64) -> TokenizationBook {
        let mut book = TokenizationBook::default();
        book.register_token_series(
            RegisterTokenSeries {
                operation_id: id(61),
                token_series: token_series(TransferRestriction::Unrestricted, Vec::new()),
            },
            &series(true),
            40,
        )
        .unwrap();
        book.authorize_issuance(authorization(units), &issuance(), 50)
            .unwrap();
        book
    }

    fn mint(intent: u8, units: u64) -> MintRequest {
        MintRequest {
            operation_id: id(intent),
            intent_id: id(intent + 100),
            issuance_id: id(91),
            units,
            recipient_commitment: id(200),
            tranche_id: None,
        }
    }

    #[test]
    fn token_series_cannot_promise_more_transferability_than_the_series_policy() {
        let mut book = TokenizationBook::default();
        assert_eq!(
            book.register_token_series(
                RegisterTokenSeries {
                    operation_id: id(61),
                    token_series: token_series(TransferRestriction::Unrestricted, Vec::new()),
                },
                &series(false),
                40,
            ),
            Err(TokenizationError::SeriesMismatch)
        );
        book.register_token_series(
            RegisterTokenSeries {
                operation_id: id(61),
                token_series: token_series(TransferRestriction::NonTransferable, Vec::new()),
            },
            &series(false),
            40,
        )
        .unwrap();
        assert!(book.validate().is_ok());
    }

    #[test]
    fn authorization_must_describe_the_aethel_issuance_and_fit_the_cap() {
        let mut book = book_with_authorization(600);
        let mut second = authorization(500);
        second.operation_id = id(71);
        second.issuance_id = id(81);
        second.note_id = id(82);
        let mut other = issuance();
        other.issuance_id = id(81);
        other.note_id = id(82);
        assert_eq!(
            book.authorize_issuance(second.clone(), &other, 50),
            Err(TokenizationError::SupplyExceedsAuthorization)
        );
        second.authorized_units = 400;
        let mut detached = other.clone();
        detached.zkpi_digest = id(3);
        assert_eq!(
            book.authorize_issuance(second.clone(), &detached, 50),
            Err(TokenizationError::IssuanceMismatch)
        );
        book.authorize_issuance(second, &other, 50).unwrap();
        assert!(book.validate().is_ok());
    }

    #[test]
    fn supply_never_exceeds_the_bound_authorization_even_while_pending() {
        let mut book = book_with_authorization(100);
        let mut ledger = Ledger {
            sequence: 0,
            reject: false,
        };
        let first = book.mint(mint(1, 60), 55).unwrap();
        assert_eq!(
            book.mint(mint(2, 41), 55),
            Err(TokenizationError::SupplyExceedsAuthorization)
        );
        let second = book.mint(mint(2, 40), 55).unwrap();
        let receipt = book.submit(&first.intent_id, &mut ledger).unwrap();
        assert_eq!(book.submit(&first.intent_id, &mut ledger).unwrap(), receipt);
        assert_eq!(ledger.sequence, 1);
        book.submit(&second.intent_id, &mut ledger).unwrap();
        assert_eq!(book.outstanding_units(&id(60)), 100);
        assert_eq!(
            book.mint(mint(3, 1), 56),
            Err(TokenizationError::SupplyExceedsAuthorization)
        );
        assert!(book.validate().is_ok());
        assert!(book.root().is_ok());
    }

    #[test]
    fn a_rejected_intent_releases_its_units() {
        let mut book = book_with_authorization(100);
        let intent = book.mint(mint(1, 100), 55).unwrap();
        let mut ledger = Ledger {
            sequence: 0,
            reject: true,
        };
        assert_eq!(
            book.submit(&intent.intent_id, &mut ledger),
            Err(TokenizationError::IntentRejected)
        );
        assert_eq!(book.account(&id(91)).unwrap().pending_mint, 0);
        assert!(book.mint(mint(2, 100), 56).is_ok());
        assert!(book.validate().is_ok());
    }

    #[test]
    fn burns_follow_the_redemption_conditions_and_the_minted_supply() {
        let mut book = book_with_authorization(100);
        let mut ledger = Ledger {
            sequence: 0,
            reject: false,
        };
        let minted = book.mint(mint(1, 100), 55).unwrap();
        book.submit(&minted.intent_id, &mut ledger).unwrap();
        let burn = |intent: u8, units: u64, reason: BurnReason| BurnRequest {
            operation_id: id(intent),
            intent_id: id(intent + 100),
            issuance_id: id(91),
            units,
            holder_commitment: id(200),
            tranche_id: None,
            reason,
        };
        assert_eq!(
            book.burn(burn(2, 10, BurnReason::GuaranteeClaim), 70),
            Err(TokenizationError::RedemptionNotPermitted)
        );
        assert_eq!(
            book.burn(burn(2, 101, BurnReason::Redemption), 70),
            Err(TokenizationError::BurnExceedsSupply)
        );
        let redeemed = book.burn(burn(2, 100, BurnReason::Redemption), 70).unwrap();
        assert_eq!(
            book.set_status(id(5), &id(60), TokenSeriesStatus::Redeemed),
            Err(TokenizationError::TokenSeriesUnavailable)
        );
        book.submit(&redeemed.intent_id, &mut ledger).unwrap();
        assert_eq!(book.outstanding_units(&id(60)), 0);
        book.set_status(id(5), &id(60), TokenSeriesStatus::Redeemed)
            .unwrap();
        assert!(book.validate().is_ok());
    }

    #[test]
    fn tranche_caps_partition_the_issuance_cap() {
        let tranches = vec![
            Tranche {
                tranche_id: id(41),
                loss_layer: LossLayer::FirstLoss,
                unit_cap: 200,
            },
            Tranche {
                tranche_id: id(42),
                loss_layer: LossLayer::Excess,
                unit_cap: 800,
            },
        ];
        let mut book = TokenizationBook::default();
        book.register_token_series(
            RegisterTokenSeries {
                operation_id: id(61),
                token_series: token_series(TransferRestriction::Unrestricted, tranches),
            },
            &series(true),
            40,
        )
        .unwrap();
        book.authorize_issuance(authorization(1_000), &issuance(), 50)
            .unwrap();
        let mut request = mint(1, 201);
        request.tranche_id = Some(id(41));
        assert_eq!(
            book.mint(request.clone(), 55),
            Err(TokenizationError::SupplyExceedsAuthorization)
        );
        request.units = 200;
        book.mint(request, 55).unwrap();
        assert_eq!(
            book.mint(mint(2, 1), 55),
            Err(TokenizationError::UnknownTranche)
        );
        let mut bad = token_series(TransferRestriction::Unrestricted, Vec::new());
        bad.tranches = vec![Tranche {
            tranche_id: id(41),
            loss_layer: LossLayer::FirstLoss,
            unit_cap: 1,
        }];
        assert_eq!(
            bad.validate_initial(),
            Err(TokenizationError::InvalidTokenSeries)
        );
    }

    #[test]
    fn the_book_keeps_no_record_keyed_by_a_holder() {
        let mut book = book_with_authorization(100);
        let mut ledger = Ledger {
            sequence: 0,
            reject: false,
        };
        let mut to_b = mint(2, 40);
        to_b.recipient_commitment = id(201);
        for request in [mint(1, 60), to_b] {
            let intent = book.mint(request, 55).unwrap();
            book.submit(&intent.intent_id, &mut ledger).unwrap();
        }
        let holders = [id_key(&id(200)), id_key(&id(201))];
        fn keys(value: &serde_json::Value, out: &mut Vec<String>) {
            match value {
                serde_json::Value::Object(map) => {
                    for (key, inner) in map {
                        out.push(key.clone());
                        keys(inner, out);
                    }
                }
                serde_json::Value::Array(items) => items.iter().for_each(|item| keys(item, out)),
                _ => {}
            }
        }
        let mut all = Vec::new();
        keys(&serde_json::to_value(&book).unwrap(), &mut all);
        assert!(holders.iter().all(|holder| !all.contains(holder)));
        assert!(all.iter().all(|key| !key.contains("balance")));
    }
}
