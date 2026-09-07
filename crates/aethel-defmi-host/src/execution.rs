use crate::state::State;
pub(crate) use defmi_avalanche_vm::application::{authorize, require_keys};
use defmi::facility::QuorumAuthorizer;
use serde_json::{Map, Value};

mod aethel;
mod deccp;

pub(crate) fn execute(
    state: &mut State,
    method: &str,
    params: &Map<String, Value>,
    authorizer: &QuorumAuthorizer,
    timestamp: u64,
) -> Result<[u8; 32], String> {
    match method {
        "defmivm.issueAethelProvider" => {
            aethel::register_provider(state, params, authorizer, timestamp)
        }
        "defmivm.issueAethelStream" => {
            aethel::register_stream(state, params, authorizer, timestamp)
        }
        "defmivm.issueAethelStreamTransition" => {
            aethel::transition_stream(state, params, authorizer, timestamp)
        }
        "defmivm.issueAethelSeries" => {
            aethel::register_series(state, params, authorizer, timestamp)
        }
        "defmivm.issueAethelCredentialIssuer" => {
            aethel::register_credential_issuer(state, params, authorizer, timestamp)
        }
        "defmivm.issueAethelCredentialStatus" => {
            aethel::publish_credential_status(state, params, authorizer, timestamp)
        }
        "defmivm.issueAethelCreditDecision" => {
            aethel::record_credit_decision(state, params, authorizer, timestamp)
        }
        "defmivm.issueAethelGuarantee" => {
            aethel::record_guarantee(state, params, authorizer, timestamp)
        }
        "defmivm.issueAethelFundingQuote" => {
            aethel::record_funding_quote(state, params, authorizer, timestamp)
        }
        "defmivm.issueAethelReceivable" => {
            aethel::issue_receivable(state, params, authorizer, timestamp)
        }
        "defmivm.issueAethelDefault" => {
            aethel::record_default(state, params, authorizer, timestamp)
        }
        "defmivm.issueAethelGuaranteeClaim" => {
            aethel::claim_guarantee(state, params, authorizer, timestamp)
        }
        "defmivm.issueAethelGuaranteeRelease" => {
            aethel::release_guarantee(state, params, authorizer, timestamp)
        }
        "defmivm.issueAethelProviderKeyRotation" => {
            aethel::rotate_provider_key(state, params, authorizer, timestamp)
        }
        "defmivm.issueAethelProviderStatus" => {
            aethel::set_provider_status(state, params, authorizer, timestamp)
        }
        "defmivm.issueDeccpClearingBook" => {
            deccp::open_clearing_book(state, params, authorizer, timestamp)
        }
        "defmivm.issueDeccpMember" => deccp::admit_member(state, params, authorizer, timestamp),
        "defmivm.issueDeccpGuaranteeFacility" => {
            deccp::register_guarantee_facility(state, params, authorizer, timestamp)
        }
        _ => Err("unknown Aethel application method".into()),
    }
}

#[cfg(test)]
mod aethel_tests;
#[cfg(test)]
mod deccp_tests;
