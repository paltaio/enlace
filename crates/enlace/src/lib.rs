#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

pub mod config;
pub mod crypto;
pub mod dedup;
pub mod error;
pub mod guard;
pub mod kdf;
pub mod mailbox;
pub mod namespace;
pub mod slot;
pub mod state;
pub mod transports;

pub use config::{BasicAuth, Config, DhtConfig, HttpConfig, IrohConfig, PkarrConfig};
pub use error::{OpenError, RecvError, SealError, SendError, SlotError, TransportError};
pub use kdf::{NameError, TransportKind};
pub use mailbox::{Mailbox, RecvMessage, SendReport};
pub use namespace::Namespace;
pub use slot::{PutReport, Slot, SlotValue, SlotWatch};
pub use state::{DhtBootstrapCache, InMemoryStateStore, StateError, StateStore};
pub use transports::{
    DhtTransport, HealthReport, HttpTransport, IrohTransport, PkarrTransport, TransportHealth,
};
