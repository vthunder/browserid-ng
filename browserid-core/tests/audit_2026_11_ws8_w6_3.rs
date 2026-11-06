//! WS8 PoC — W6-3 / W5-8: the status-list decoder used to inflate the whole
//! zlib stream before the 4 MiB cap. In-process; the same `StatusList::decode`
//! is reached unauthenticated via the broker's GET /status/proxy (WS5).
//! Flipped with the fix (bean rn46): the same bomb now rejects with process
//! RSS staying near the cap.
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
fn w6_3_poc_zlib_bomb_is_rejected_without_allocating_past_the_cap() {
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
    let grew = peak_mib.saturating_sub(base_mib);
    println!(
        "[W6-3] decode returned {:?}; process RSS {} MiB -> peak {} MiB (grew {} MiB on a {}-byte request; 4 MiB cap)",
        res.as_ref().map(|_| "Ok").map_err(|e| e.to_string()),
        base_mib, peak_mib, grew, lst.len()
    );
    // The cap now bounds the inflate itself: decode errors AND the process
    // never grows past a few multiples of the cap (the 768 MiB inflate is
    // never performed).
    assert!(res.is_err(), "the 4 MiB cap rejects the oversized list");
    assert!(grew < 32, "RSS grew {grew} MiB past the cap on a rejected list");
}
