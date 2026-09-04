//! Aethel: programmable payment-stream receivables.
//!
//! The payment stream itself becomes the receivable, and independent credit,
//! guarantee, funding, and servicing providers plug into it. This crate is the
//! single entry point over the module crates, each of which is usable on its
//! own:
//!
//! | module | crate | owns |
//! |---|---|---|
//! | [`types`] | `aethel-types` | identifiers, commitments, canonical digests |
//! | [`provider`] | `aethel-provider-sdk` | the provider plug-in contract and every provider-signed artifact |
//! | [`protocol`] | `aethel-core` | the authoritative Aethel book: streams, series, issuance, default, claim |
//! | [`tokenization`] | `aethel-tokenization` | token series, supply caps, and supply intents for the asset ledger |
//! | [`distribution`] | `aethel-distribution` | venue-neutral circulation requests, fills, and settlement contexts |
//! | [`obligation_wallet`] | `aethel-obligation-wallet` | the obligor's schedule, pre-authorization, queue, and reconciliation |
//! | [`servicing`] | `aethel-servicing` | payment evidence, delinquency, cure, and evidence-backed default |
//!
//! What Aethel does not own stays outside: DeKYX is the credential layer,
//! DeCCP holds guarantee capacity and the loss waterfall, DeFMI is the cash,
//! security, and receivable-token ledger, and zkPI is the typed settlement
//! instruction. The module crates reach those systems through ports and
//! digests, never by reimplementing them.

#![forbid(unsafe_code)]

pub use aethel_core as protocol;
pub use aethel_distribution as distribution;
pub use aethel_obligation_wallet as obligation_wallet;
pub use aethel_provider_sdk as provider;
pub use aethel_servicing as servicing;
pub use aethel_tokenization as tokenization;
pub use aethel_types as types;

/// The names a host adapter needs most often.
pub mod prelude {
    pub use aethel_core::{
        AethelBook, AethelError, ConfidentialArtifact, GuaranteeClaim, ReceivableIssuance,
        ReceivableSeries, ReceivableStatus, RegisterSeries, RegisteredStream, SeriesPolicy,
    };
    pub use aethel_distribution::{
        CirculationRequest, DistributionBook, DistributionError, SettlementContext,
        SettlementOutcome, Side, Venue, VenueFill, VenueHandoff,
    };
    pub use aethel_obligation_wallet::{
        EnqueueOutcome, ObligationWallet, PaymentSchedule, PreAuthorization, Reconciliation,
        RetryPolicy, SettlementReceipt, SignedPayment, SigningRequest, WalletError,
    };
    pub use aethel_provider_sdk::{
        sign_artifact, CreditDecision, DefaultAttestation, FundingQuote, GuaranteeCommitment,
        GuaranteeRelease, ProviderCapability, ProviderDefinition, ProviderError, ProviderRegistry,
        ProviderStatus, RegisterProvider, RegisterStream, RotateProviderKey, SetProviderStatus,
        SignedArtifact, StreamState, StreamStatus, StreamTransition,
    };
    pub use aethel_servicing::{
        DefaultEvidence, PaymentEvidence, ServicingBook, ServicingError, ServicingStatus,
        ServicingTerms,
    };
    pub use aethel_tokenization::{
        AssetLedgerPort, BurnRequest, IssuanceAuthorization, MintRequest, RegisterTokenSeries,
        SupplyIntent, SupplyReceipt, TokenSeries, TokenizationBook, TokenizationError,
        TransferRestriction,
    };
    pub use aethel_types::{Commitment, Identifier, MAX_UNIX_TIME, ZERO};
}
