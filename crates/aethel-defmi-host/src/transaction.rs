//! Construct generic DeFMI envelopes with an application-owned payload.

use serde_json::{json, Value};

/// Convenience constructor. The returned envelope remains the generic DeFMI
/// wire type; legacy application names occur only inside its application payload.
pub struct TransactionEnvelope(qomm_avalanche_vm::transaction::TransactionEnvelope);

impl TransactionEnvelope {
    pub fn new(method: impl Into<String>, params: Value) -> Result<Self, String> {
        let method = method.into();
        if crate::METHODS.contains(&method.as_str()) {
            qomm_avalanche_vm::transaction::TransactionEnvelope::new(
                "defmivm.issueApplication",
                json!({ "application": crate::APPLICATION_ID, "method": method, "params": params }),
            )
            .map(Self)
        } else {
            qomm_avalanche_vm::transaction::TransactionEnvelope::new(method, params).map(Self)
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.0.encode()
    }
}
