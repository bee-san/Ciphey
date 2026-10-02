//! Progress of the running search, for the live display (`crate::tui`).
//!
//! The A* loop records one update per batch of nodes, never per decoder call, and the
//! display reads the numbers on its own thread a few times a second. Unless the display
//! turned reporting on with [`enable`], an update is a single relaxed atomic load, so
//! library users, the benchmarks and plain output don't pay for it.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

/// A copy of the progress at one moment
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// Texts whose decoders have all been run
    pub expanded: u64,
    /// The deepest layer reached
    pub depth: u32,
    /// Decoders that produced the most promising text being expanded
    pub trying: Vec<&'static str>,
    /// Whether the answer came from the cache
    pub cache_hit: bool,
}

impl Snapshot {
    /// How many layers of decoding have been tried: expanding the input tries one
    /// layer, expanding what that produced tries a second, and so on
    pub fn layers(&self) -> u32 {
        if self.expanded == 0 {
            0
        } else {
            self.depth + 1
        }
    }
}

/// The counters the search updates
struct Progress {
    /// Whether anyone is reading the progress
    enabled: AtomicBool,
    /// Texts whose decoders have all been run
    expanded: AtomicU64,
    /// The deepest layer reached so far
    depth: AtomicU32,
    /// Whether the answer came from the cache instead of a search
    cache_hit: AtomicBool,
    /// Decoders that produced the most promising text being expanded right now
    trying: Mutex<Vec<&'static str>>,
}

impl Progress {
    /// Counters at zero, not recording
    const fn new() -> Self {
        Progress {
            enabled: AtomicBool::new(false),
            expanded: AtomicU64::new(0),
            depth: AtomicU32::new(0),
            cache_hit: AtomicBool::new(false),
            trying: Mutex::new(Vec::new()),
        }
    }

    /// See [`enable`]
    fn enable(&self) {
        self.reset();
        self.enabled.store(true, Ordering::Relaxed);
    }

    /// See [`disable`]
    fn disable(&self) {
        self.enabled.store(false, Ordering::Relaxed);
    }

    /// Sets every counter back to zero
    fn reset(&self) {
        self.expanded.store(0, Ordering::Relaxed);
        self.depth.store(0, Ordering::Relaxed);
        self.cache_hit.store(false, Ordering::Relaxed);
        if let Ok(mut trying) = self.trying.lock() {
            trying.clear();
        }
    }

    /// See [`record_batch`]
    fn record_batch<'a>(
        &self,
        expanded: usize,
        depth: u32,
        best_path: impl FnOnce() -> Option<&'a [crate::CrackResult]>,
    ) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        self.expanded.fetch_add(expanded as u64, Ordering::Relaxed);
        self.depth.fetch_max(depth, Ordering::Relaxed);
        // try_lock: if the display is reading the list right now, skip this update
        // rather than make the search wait
        if let (Some(path), Ok(mut trying)) = (best_path(), self.trying.try_lock()) {
            trying.clear();
            trying.extend(path.iter().map(|step| step.decoder));
        }
    }

    /// See [`record_cache_hit`]
    fn record_cache_hit(&self) {
        if self.enabled.load(Ordering::Relaxed) {
            self.cache_hit.store(true, Ordering::Relaxed);
        }
    }

    /// See [`snapshot`]
    fn snapshot(&self) -> Snapshot {
        Snapshot {
            expanded: self.expanded.load(Ordering::Relaxed),
            depth: self.depth.load(Ordering::Relaxed),
            trying: self.trying.lock().map(|t| t.clone()).unwrap_or_default(),
            cache_hit: self.cache_hit.load(Ordering::Relaxed),
        }
    }
}

/// The progress of this process's search
static PROGRESS: Progress = Progress::new();

/// Starts recording progress, from zero
pub fn enable() {
    PROGRESS.enable();
}

/// Stops recording progress
pub fn disable() {
    PROGRESS.disable();
}

/// Records one batch of the A* loop: how many nodes it expands, the deepest layer
/// reached so far, and the decoder path of the most promising node in the batch.
pub fn record_batch<'a>(
    expanded: usize,
    depth: u32,
    best_path: impl FnOnce() -> Option<&'a [crate::CrackResult]>,
) {
    PROGRESS.record_batch(expanded, depth, best_path);
}

/// Records that the answer came straight from the cache
pub fn record_cache_hit() {
    PROGRESS.record_cache_hit();
}

/// The progress so far
pub fn snapshot() -> Snapshot {
    PROGRESS.snapshot()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoders::crack_results::CrackResult;
    use crate::decoders::interface::Decoder;

    #[test]
    fn batches_are_only_recorded_while_enabled() {
        // Its own counters: searches in other tests record into the global ones
        let progress = Progress::new();
        let mut step = CrackResult::new(&Decoder::default(), String::new());
        step.decoder = "Base64";
        let path = vec![step];

        progress.record_batch(10, 2, || Some(&path));
        progress.record_cache_hit();
        assert_eq!(progress.snapshot(), Snapshot::default());

        progress.enable();
        progress.record_batch(10, 2, || Some(&path));
        progress.record_batch(5, 1, || None);
        let snapshot = progress.snapshot();
        assert_eq!(snapshot.expanded, 15);
        assert_eq!(snapshot.depth, 2);
        assert_eq!(snapshot.layers(), 3);
        assert_eq!(snapshot.trying, vec!["Base64"]);
        assert!(!snapshot.cache_hit);

        progress.record_cache_hit();
        assert!(progress.snapshot().cache_hit);

        // Enabling again starts from zero
        progress.enable();
        assert_eq!(progress.snapshot(), Snapshot::default());
        assert_eq!(Snapshot::default().layers(), 0);
    }
}
