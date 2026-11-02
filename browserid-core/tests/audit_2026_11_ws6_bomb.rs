//! Security audit 2026-11, WS6 — W6-3 / WS5 W5-8: `StatusList::decode` must
//! bound the INFLATED size before allocating, not after.
//!
//! Lives in its own test binary because it installs a counting global
//! allocator. The hosted fetch caps the transport body at 4 MiB, but zlib
//! inflates up to ~1032:1, so a body under that cap can inflate to gigabytes
//! before `decode` compares `bytes.len()` to its 4 MiB ceiling. Reachable
//! unauthenticated through `/status/proxy` and every foreign status fetch.
//!
//! Report: docs/security-audit-2026-11-ws6-core-verifier.md.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use browserid_core::StatusList;

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

/// zlib-compress `inflated` zero bytes (compresses ~1000:1).
fn bomb(inflated: usize) -> String {
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    let chunk = vec![0u8; 1 << 20];
    let mut left = inflated;
    while left > 0 {
        let n = left.min(chunk.len());
        enc.write_all(&chunk[..n]).unwrap();
        left -= n;
    }
    B64.encode(enc.finish().unwrap())
}

const MIB: usize = 1024 * 1024;

#[test]
#[ignore] // AUDIT-2026-11 W6-3 (WS5 W5-8): fails today — `read_to_end` inflates everything, then checks the 4 MiB cap (status.rs:96-108)
fn w6_3_oversized_status_list_is_rejected_without_inflating_it() {
    // 256 MiB of zeros compresses to ~256 KiB — far under the transport cap.
    let lst = bomb(256 * MIB);
    assert!(lst.len() < 2 * MIB, "bomb must fit the 4 MiB transport cap; got {}", lst.len());

    PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
    let r = StatusList::decode(&lst);
    let peak = PEAK.load(Ordering::Relaxed);

    assert!(r.is_err(), "an over-cap list must reject");
    assert!(
        peak < 16 * MIB,
        "decode allocated {} MiB for a list it then rejected; the cap must bound the inflate",
        peak / MIB
    );
}

/// The cap itself works once the bytes exist — a list just under it decodes.
#[test]
fn status_list_under_the_cap_decodes() {
    let lst = bomb(MIB);
    assert!(StatusList::decode(&lst).is_ok());
}
