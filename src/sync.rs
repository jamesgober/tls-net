//! Synchronisation types: `std` normally, loom's under `cfg(tls_net_loom)`, so
//! the snapshot, the capacity gate, and the ticket ring can be model-checked
//! (NFR-20).

#[cfg(not(tls_net_loom))]
pub(crate) use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
#[cfg(not(tls_net_loom))]
pub(crate) use std::sync::{Arc as Shared, Mutex, RwLock};

#[cfg(tls_net_loom)]
pub(crate) use loom::sync::atomic::{AtomicU32, AtomicU64, Ordering};
#[cfg(tls_net_loom)]
pub(crate) use loom::sync::{Arc as Shared, Mutex, RwLock};
