//! Aethel owns the application runtime; DeFMI owns the generic ledger and VM.
//! Instantiate `vm()` only for an Aethel host. The default DeFMI binary has no
//! dependency on this crate, no Aethel methods and no Aethel state decoder.

use std::sync::Arc;

use defmi_avalanche_vm::{application::ApplicationRuntime, state::State as LedgerState, QommVm};
use defmi::facility::QuorumAuthorizer;
use serde_json::{Map, Value};

mod clearing_state;
mod execution;
mod methods;
pub mod state;
pub mod transaction;

pub use methods::METHODS;

pub const APPLICATION_ID: &str = "aethel.v1";
#[derive(Default)]
pub struct AethelRuntime;

impl ApplicationRuntime for AethelRuntime {
    fn validate_state(&self, ledger: &LedgerState) -> Result<(), String> {
        state::State::from_ledger(ledger.clone()).map(|_| ())
    }

    fn execute(
        &self,
        ledger: &mut LedgerState,
        params: &Map<String, Value>,
        authorizer: &QuorumAuthorizer,
        timestamp: u64,
    ) -> Result<[u8; 32], String> {
        defmi_avalanche_vm::application::require_keys(params, &["application", "method", "params"])?;
        if params.get("application").and_then(Value::as_str) != Some(APPLICATION_ID) {
            return Err("unknown application for this Aethel host".into());
        }
        let method = params
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| "application method must be a string".to_owned())?;
        let fields = params
            .get("params")
            .and_then(Value::as_object)
            .ok_or_else(|| "application params must be an object".to_owned())?;
        let mut state = state::State::from_ledger(ledger.clone())?;
        let statement = execution::execute(&mut state, method, fields, authorizer, timestamp)?;
        state.validate()?;
        *ledger = state.into_ledger()?;
        Ok(statement)
    }
}

pub fn vm() -> QommVm {
    QommVm::with_application(Arc::new(AethelRuntime))
}
