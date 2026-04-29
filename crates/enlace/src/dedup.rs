//! Best-effort dedup of recently-seen sealed payloads.
//!
//! Fan-out delivers the same ciphertext on multiple transports; a small LRU of
//! sha256 hashes lets the coordinator surface each payload exactly once per
//! channel within a short window. This is **not** replay protection — durable
//! replay rejection is the consumer's job, layered on top with its own message
//! identifiers and journal.

use std::num::NonZeroUsize;

use lru::LruCache;
use sha2::{Digest, Sha256};

/// Default number of recently-seen sealed-payload hashes retained per channel.
pub const DEFAULT_CAPACITY: usize = 1024;

/// Length in bytes of the sha256 digest used as the cache key.
pub const DIGEST_LEN: usize = 32;

/// Bounded ring of sealed-payload digests.
///
/// Constructed with a capacity in number of entries. Capacity zero disables
/// dedup entirely — every observation reports as new — which is the documented
/// way to opt out for callers willing to surface duplicates across transports.
pub struct Dedup {
    cache: Option<LruCache<[u8; DIGEST_LEN], ()>>,
}

impl Dedup {
    /// Create a dedup buffer that retains at most `capacity` recent digests.
    ///
    /// `capacity == 0` produces a disabled buffer: [`observe`](Self::observe)
    /// always returns `false`.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let cache = NonZeroUsize::new(capacity).map(LruCache::new);
        Self { cache }
    }

    /// Hash `sealed` and record it.
    ///
    /// Returns `true` when the digest was already present (caller should drop
    /// the message), `false` when it is new (and now inserted) or when the
    /// buffer is disabled.
    pub fn observe(&mut self, sealed: &[u8]) -> bool {
        let Some(cache) = self.cache.as_mut() else {
            return false;
        };
        let digest = digest(sealed);
        cache.put(digest, ()).is_some()
    }

    /// Number of entries currently retained. Returns 0 when disabled.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cache.as_ref().map_or(0, LruCache::len)
    }

    /// True when no entries are retained, including when disabled.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.as_ref().is_none_or(LruCache::is_empty)
    }

    /// Configured capacity. Returns 0 when disabled.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.cache.as_ref().map_or(0, |c| c.cap().get())
    }

    /// Drop every retained digest. No-op when disabled.
    pub fn clear(&mut self) {
        if let Some(cache) = self.cache.as_mut() {
            cache.clear();
        }
    }
}

impl Default for Dedup {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

fn digest(sealed: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(sealed);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn fresh_observation_is_not_a_duplicate() {
        let mut d = Dedup::new(8);
        assert!(!d.observe(b"hello"));
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn repeated_observation_is_a_duplicate() {
        let mut d = Dedup::new(8);
        assert!(!d.observe(b"hello"));
        assert!(d.observe(b"hello"));
        assert!(d.observe(b"hello"));
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn distinct_payloads_are_independent() {
        let mut d = Dedup::new(8);
        assert!(!d.observe(b"a"));
        assert!(!d.observe(b"b"));
        assert!(!d.observe(b"c"));
        assert!(d.observe(b"a"));
        assert!(d.observe(b"b"));
        assert!(d.observe(b"c"));
        assert_eq!(d.len(), 3);
    }

    #[test]
    fn evicts_least_recently_used_at_capacity() {
        let mut d = Dedup::new(2);
        assert!(!d.observe(b"a"));
        assert!(!d.observe(b"b"));
        // touch "a" so "b" becomes LRU
        assert!(d.observe(b"a"));
        // inserting "c" should evict "b"
        assert!(!d.observe(b"c"));
        assert_eq!(d.len(), 2);
        // "b" is gone — re-observing reports new
        assert!(!d.observe(b"b"));
        // ...which evicted "a" (now LRU after the b/c sequence)
        assert!(!d.observe(b"a"));
    }

    #[test]
    fn capacity_zero_disables_dedup() {
        let mut d = Dedup::new(0);
        assert_eq!(d.capacity(), 0);
        assert!(d.is_empty());
        assert!(!d.observe(b"hello"));
        assert!(!d.observe(b"hello"));
        assert!(!d.observe(b"hello"));
        assert_eq!(d.len(), 0);
        assert!(d.is_empty());
    }

    #[test]
    fn capacity_reports_configured_value() {
        assert_eq!(Dedup::new(1).capacity(), 1);
        assert_eq!(Dedup::new(1024).capacity(), 1024);
        assert_eq!(Dedup::new(0).capacity(), 0);
    }

    #[test]
    fn default_uses_documented_capacity() {
        let d = Dedup::default();
        assert_eq!(d.capacity(), DEFAULT_CAPACITY);
        assert!(d.is_empty());
    }

    #[test]
    fn empty_payload_is_observable() {
        let mut d = Dedup::new(4);
        assert!(!d.observe(b""));
        assert!(d.observe(b""));
    }

    #[test]
    fn clear_removes_all_entries() {
        let mut d = Dedup::new(4);
        d.observe(b"a");
        d.observe(b"b");
        assert_eq!(d.len(), 2);
        d.clear();
        assert!(d.is_empty());
        // after clear, prior entries are no longer duplicates
        assert!(!d.observe(b"a"));
        assert!(!d.observe(b"b"));
    }

    #[test]
    fn clear_on_disabled_is_noop() {
        let mut d = Dedup::new(0);
        d.observe(b"a");
        d.clear();
        assert!(d.is_empty());
        assert!(!d.observe(b"a"));
    }

    #[test]
    fn distinct_inputs_with_same_length_distinguished_by_hash() {
        let mut d = Dedup::new(8);
        let a = vec![0u8; 64];
        let mut b = vec![0u8; 64];
        b[63] = 1;
        assert!(!d.observe(&a));
        assert!(!d.observe(&b));
        assert!(d.observe(&a));
        assert!(d.observe(&b));
    }

    #[test]
    fn digest_is_sha256_of_input() {
        // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let want: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(digest(b""), want);
    }

    proptest! {
        #[test]
        fn repeated_payload_is_duplicate(payload in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let mut d = Dedup::new(32);
            prop_assert!(!d.observe(&payload));
            prop_assert!(d.observe(&payload));
        }

        #[test]
        fn disabled_buffer_never_reports_duplicate(payload in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let mut d = Dedup::new(0);
            prop_assert!(!d.observe(&payload));
            prop_assert!(!d.observe(&payload));
            prop_assert_eq!(d.len(), 0);
        }
    }
}
