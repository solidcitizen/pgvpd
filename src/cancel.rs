//! Query-cancel routing for pooled sessions.
//!
//! In pool mode pgvpd hands each client its OWN minted BackendKeyData, never the
//! real upstream key (which is shared across every client of a bucket). This
//! registry maps a client's minted `(pid, secret)` to the real upstream backend
//! key of the connection it is *currently* using, so a client's CancelRequest is
//! routed only to its own in-flight query — never another tenant's. Entries live
//! exactly as long as the client's checkout: registered when the pooled session
//! begins, removed (via [`CancelGuard`]) when it ends or is cancelled.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// The real upstream backend key a client's minted cancel key maps to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CancelTarget {
    pub pid: u32,
    pub secret: u32,
}

/// Client minted cancel key: the `(pid, secret)` pgvpd handed the client.
type ClientKey = (u32, u32);

/// Maps each active client's minted cancel key to its upstream target.
pub struct CancelRegistry {
    map: Mutex<HashMap<ClientKey, CancelTarget>>,
}

impl CancelRegistry {
    pub fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<ClientKey, CancelTarget>> {
        self.map.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Register a client key → upstream target for the life of the returned
    /// guard. Dropping the guard removes the entry, so a cancelled or finished
    /// session leaves nothing routable behind.
    pub fn register(self: &Arc<Self>, client: ClientKey, target: CancelTarget) -> CancelGuard {
        self.lock().insert(client, target);
        CancelGuard {
            registry: Arc::clone(self),
            client,
        }
    }

    /// Resolve a client's cancel key to its upstream target, if it is a live
    /// session. An unknown or stale key returns `None` (the cancel is a no-op).
    pub fn lookup(&self, client: ClientKey) -> Option<CancelTarget> {
        self.lock().get(&client).copied()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock().len()
    }
}

/// Removes its registry entry on drop — including when the pooled session's
/// future is cancelled mid-flight — so a cancel key never outlives its session.
pub struct CancelGuard {
    registry: Arc<CancelRegistry>,
    client: ClientKey,
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        self.registry.lock().remove(&self.client);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_lookup_unregister_on_drop() {
        let reg = Arc::new(CancelRegistry::new());
        let target = CancelTarget {
            pid: 111,
            secret: 222,
        };
        {
            let _guard = reg.register((1, 2), target);
            assert_eq!(reg.lookup((1, 2)), Some(target));
            assert_eq!(reg.len(), 1);
        }
        // Guard dropped — entry gone.
        assert_eq!(reg.lookup((1, 2)), None);
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn unknown_key_is_no_op() {
        let reg = Arc::new(CancelRegistry::new());
        let _g = reg.register((1, 2), CancelTarget { pid: 9, secret: 9 });
        // A different (forged/stale) key resolves to nothing.
        assert_eq!(reg.lookup((3, 4)), None);
        assert_eq!(reg.lookup((1, 999)), None);
    }

    #[test]
    fn distinct_clients_map_to_distinct_targets() {
        let reg = Arc::new(CancelRegistry::new());
        let a = CancelTarget {
            pid: 10,
            secret: 20,
        };
        let b = CancelTarget {
            pid: 30,
            secret: 40,
        };
        let _ga = reg.register((1, 1), a);
        let _gb = reg.register((2, 2), b);
        assert_eq!(reg.lookup((1, 1)), Some(a));
        assert_eq!(reg.lookup((2, 2)), Some(b));
    }
}
