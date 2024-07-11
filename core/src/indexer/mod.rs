mod process;
mod progress;

pub use progress::{IndexingEventProgressStatus, IndexingEventsProgressState};
use serde::{Deserialize, Serialize};

mod log_helpers;
pub use log_helpers::parse_topic;
mod dependency;
pub use dependency::ContractEventDependenciesMapFromRelationshipsError;
mod fetch_logs;
mod last_synced;
pub mod no_code;
mod reorg;
pub mod start;
use crate::manifest::contract::Contract;
pub use dependency::{ContractEventDependencies, EventDependencies, EventsDependencyTree};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Indexer {
    pub name: String,

    pub contracts: Vec<Contract>,
}
