//! Security audit 2026-11, WS3 — randomized form of WS6 W6-3: the status-list
//! decoder's allocation must be bounded by its own cap for ANY input, not
//! just for well-formed lists. Own binary because it installs a counting
//! global allocator (same device as `audit_2026_11_ws6_bomb.rs`).
//!
//! Report: docs/security-audit-2026-11-ws3-fuzz-proptest.md.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use browserid_core::StatusList;
use proptest::prelude::*;

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let now = LIVE.fetch_add(l.size(), Ordering::Relaxed) + l.size();
        PEAK.fetch_max(now, Ordering::Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        System.dealloc(p, l)
    }
}

#[global_allocator]
static A: Counting = Counting;

const MIB: usize = 1024 * 1024;
/// `StatusList::decode`'s own ceiling (status.rs) plus working slack.
const CAP: usize = 4 * MIB;
const BOUND: usize = 2 * CAP;

/// zlib of `inflated` bytes of `fill` (compresses ~1000:1 for a constant).
fn bomb(inflated: usize, fill: u8) -> String {
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    let chunk = vec![fill; MIB];
    let mut left = inflated;
    while left > 0 {
        let n = left.min(chunk.len());
        enc.write_all(&chunk[..n]).unwrap();
        left -= n;
    }
    B64.encode(enc.finish().unwrap())
}

fn peak_of(f: impl FnOnce()) -> usize {
    PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
    let base = LIVE.load(Ordering::Relaxed);
    f();
    PEAK.load(Ordering::Relaxed).saturating_sub(base)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

    /// Allocation ≤ cap for every input: arbitrary bytes, and zlib streams
    /// whose inflated size is anywhere from 0 to 64 MiB. Inputs that inflate
    /// past the cap must be rejected WITHOUT the inflate.
    #[test]
    #[ignore] // AUDIT-2026-11 W6-3 (WS5 W5-8): fails today — `read_to_end` inflates everything before the 4 MiB cap is compared (status.rs:96-108)
    fn decode_allocation_is_bounded_for_any_input(inflated_mib in 0usize..=64, fill in any::<u8>(), noise in proptest::collection::vec(any::<u8>(), 0..512)) {
        let lst = bomb(inflated_mib * MIB, fill);
        let peak = peak_of(|| { let _ = StatusList::decode(&lst); });
        prop_assert!(peak <= BOUND, "{} MiB inflated → {} MiB allocated", inflated_mib, peak / MIB);
        let peak = peak_of(|| { let _ = StatusList::decode(&B64.encode(&noise)); });
        prop_assert!(peak <= BOUND);
    }

    /// The bound already holds for inputs under the cap (so the fixed decoder
    /// must not regress the honest path) and for non-zlib noise.
    #[test]
    fn decode_allocation_is_bounded_under_the_cap(inflated_mib in 0usize..=3, fill in any::<u8>(), noise in proptest::collection::vec(any::<u8>(), 0..512)) {
        let lst = bomb(inflated_mib * MIB, fill);
        let peak = peak_of(|| { assert!(StatusList::decode(&lst).is_ok()); });
        prop_assert!(peak <= BOUND, "{} MiB inflated → {} MiB allocated", inflated_mib, peak / MIB);
        let peak = peak_of(|| { let _ = StatusList::decode(&B64.encode(&noise)); });
        prop_assert!(peak <= BOUND);
    }
}
