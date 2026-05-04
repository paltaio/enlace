//! Cross-target async spawn helper and timing primitives.
//!
//! Native uses `tokio::spawn` and `tokio::time`. Wasm uses
//! `wasm_bindgen_futures::spawn_local`, `web_time::Instant`, and
//! `gloo_timers::future` because `std::time::Instant` and tokio's timer driver
//! both panic on `wasm32-unknown-unknown`. The returned [`AbortHandle`] aborts
//! the task on native and is a no-op on wasm where `spawn_local` exposes no
//! cancellation primitive.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

#[cfg(not(target_arch = "wasm32"))]
pub use std::time::{Instant, SystemTime};

#[cfg(target_arch = "wasm32")]
pub use web_time::{Instant, SystemTime};

/// Async sleep that picks a target-appropriate timer source.
pub async fn sleep(duration: Duration) {
    #[cfg(not(target_arch = "wasm32"))]
    {
        tokio::time::sleep(duration).await;
    }
    #[cfg(target_arch = "wasm32")]
    {
        let ms = u32::try_from(duration.as_millis()).unwrap_or(u32::MAX);
        gloo_timers::future::TimeoutFuture::new(ms).await;
    }
}

/// Indicates that a [`timeout`] expired before the wrapped future resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elapsed;

impl std::fmt::Display for Elapsed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("operation timed out")
    }
}

impl std::error::Error for Elapsed {}

/// Race a future against an instant deadline. Returns `Err(Elapsed)` if `now`
/// is already past the deadline or it expires first.
#[cfg_attr(
    not(any(feature = "iroh")),
    allow(dead_code, reason = "consumed by iroh transport only")
)]
pub async fn timeout_at<F>(deadline: Instant, future: F) -> Result<F::Output, Elapsed>
where
    F: Future,
{
    let now = Instant::now();
    let remaining = deadline.checked_duration_since(now).unwrap_or_default();
    #[cfg(not(target_arch = "wasm32"))]
    {
        tokio::time::timeout(remaining, future)
            .await
            .map_err(|_| Elapsed)
    }
    #[cfg(target_arch = "wasm32")]
    {
        use futures_util::future::Either;
        let work = std::pin::pin!(future);
        let timer = std::pin::pin!(sleep(remaining));
        match futures_util::future::select(work, timer).await {
            Either::Left((output, _)) => Ok(output),
            Either::Right(((), _)) => Err(Elapsed),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use native::{AbortHandle, spawn};

#[cfg(target_arch = "wasm32")]
#[allow(
    unused_imports,
    reason = "AbortHandle is consumed only when transport features are enabled"
)]
pub use wasm::{AbortHandle, spawn};

/// Boxed future that requires `Send` on native and is unconstrained on wasm.
/// Use to collect heterogeneous async closures into a single `FuturesUnordered`.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxedFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

#[cfg(target_arch = "wasm32")]
pub type BoxedFuture<T> = Pin<Box<dyn Future<Output = T>>>;

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use super::Future;

    pub struct AbortHandle(tokio::task::AbortHandle);

    impl AbortHandle {
        pub fn abort(&self) {
            self.0.abort();
        }
    }

    pub fn spawn<F>(future: F) -> AbortHandle
    where
        F: Future<Output = ()> + Send + 'static,
    {
        AbortHandle(tokio::spawn(future).abort_handle())
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::Future;

    pub struct AbortHandle;

    impl AbortHandle {
        // wasm_bindgen_futures exposes no cancellation; held for parity with
        // the native AbortHandle so callers don't need cfg branches.
        #[allow(dead_code)]
        pub fn abort(&self) {}
    }

    pub fn spawn<F>(future: F) -> AbortHandle
    where
        F: Future<Output = ()> + 'static,
    {
        wasm_bindgen_futures::spawn_local(future);
        AbortHandle
    }
}
