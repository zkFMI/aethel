//! Typed application state over DeFMI's opaque, committed application storage.

use std::ops::{Deref, DerefMut};

use aethel_core::AethelBook;
use defmi_avalanche_vm::state::State as LedgerState;
use defmi::facility::QuorumAuthorizer;
use serde::{de::DeserializeOwned, Serialize};

pub use defmi_avalanche_vm::state::{
    id_key, AssetRecord, CreditFacilityRecord, CreditHoldRecord, GuarantorRecord, NoteClaimRecord,
    NoteRecord, NoteSerialRecord, OpeningEnvelopeRecord, SettlementVerifierRecord,
    TransitionReceipt,
};

pub use crate::clearing_state::ClearingState;

const BOOK: &str = "aethel.book.v1";
const CLEARING: &str = "aethel.clearing.v1";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct State {
    ledger: LedgerState,
    pub aethel: AethelBook,
    pub deccp: Option<ClearingState>,
}

impl Deref for State {
    type Target = LedgerState;
    fn deref(&self) -> &Self::Target {
        &self.ledger
    }
}

impl DerefMut for State {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.ledger
    }
}

fn read<T: DeserializeOwned + Serialize>(
    ledger: &LedgerState,
    key: &str,
) -> Result<Option<T>, String> {
    let Some(bytes) = ledger.application_states.get(key) else {
        return Ok(None);
    };
    let value: T =
        serde_json::from_slice(bytes).map_err(|error| format!("invalid {key}: {error}"))?;
    if serde_json::to_vec(&value).map_err(|error| error.to_string())? != *bytes {
        return Err(format!("{key} is not canonically encoded"));
    }
    Ok(Some(value))
}

impl State {
    pub fn from_ledger(ledger: LedgerState) -> Result<Self, String> {
        if ledger
            .application_states
            .keys()
            .any(|key| key != BOOK && key != CLEARING)
        {
            return Err("Aethel host cannot validate an unknown application namespace".into());
        }
        let state = Self {
            aethel: read(&ledger, BOOK)?.unwrap_or_default(),
            deccp: read(&ledger, CLEARING)?,
            ledger,
        };
        state.validate()?;
        // Empty books are omitted. Do not accept two encodings of one state.
        if state.clone().into_ledger()?.application_states != state.ledger.application_states {
            return Err("application state contains a noncanonical empty book".into());
        }
        Ok(state)
    }

    pub fn into_ledger(mut self) -> Result<LedgerState, String> {
        self.validate()?;
        self.ledger.application_states.remove(BOOK);
        self.ledger.application_states.remove(CLEARING);
        if !self.aethel.is_empty() {
            self.ledger.application_states.insert(
                BOOK.into(),
                serde_json::to_vec(&self.aethel).map_err(|error| error.to_string())?,
            );
        }
        if let Some(clearing) = &self.deccp {
            self.ledger.application_states.insert(
                CLEARING.into(),
                serde_json::to_vec(clearing).map_err(|error| error.to_string())?,
            );
        }
        Ok(self.ledger)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.ledger.validate()?;
        self.aethel.validate().map_err(|error| error.to_string())?;
        if let Some(clearing) = &self.deccp {
            clearing
                .book
                .validate()
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    pub fn root(&self) -> [u8; 32] {
        self.clone()
            .into_ledger()
            .expect("validated application state serializes")
            .root()
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.clone().into_ledger()?.encode()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        Self::from_ledger(LedgerState::decode(bytes)?)
    }

    pub fn apply(
        &mut self,
        bytes: &[u8],
        authorizer: &QuorumAuthorizer,
        timestamp: u64,
    ) -> Result<TransitionReceipt, String> {
        let mut next = self.clone().into_ledger()?;
        let receipt =
            next.apply_with_application(bytes, authorizer, timestamp, &crate::AethelRuntime)?;
        *self = Self::from_ledger(next)?;
        Ok(receipt)
    }
}
