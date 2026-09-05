use deccp_core::{ClearingBook, ClearingSnapshot, DeCcpError};
use serde::{Deserialize, Serialize};

/// The DeCCP clearing book this VM hosts for Aethel guarantees.
///
/// `ClearingBook` deliberately has no `Deserialize`: DeCCP refuses to rebuild
/// a book from storage it cannot trust. Here the store is the VM's own
/// consensus state, whose root commits to these bytes and whose decoder
/// re-checks the canonical encoding, so the book is rebuilt through
/// `ClearingBook::restore_authenticated`, which still re-runs every DeCCP
/// structural invariant on load.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "ClearingSnapshot", into = "ClearingSnapshot")]
pub struct ClearingState {
    pub book: ClearingBook,
}

impl TryFrom<ClearingSnapshot> for ClearingState {
    type Error = DeCcpError;

    fn try_from(snapshot: ClearingSnapshot) -> Result<Self, DeCcpError> {
        ClearingBook::restore_authenticated(snapshot).map(|book| Self { book })
    }
}

impl From<ClearingState> for ClearingSnapshot {
    fn from(clearing: ClearingState) -> Self {
        clearing.book.snapshot()
    }
}
