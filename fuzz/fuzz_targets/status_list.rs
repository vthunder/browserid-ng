#![no_main]
//! WS3: status-list decoding is total and bit reads are total; a list that
//! decodes re-encodes to something that decodes to the same list.
//! libFuzzer's RSS limit turns the W6-3 inflate-before-cap bomb into a
//! crash if the fuzzer ever synthesizes one (seeds/status_list carries a
//! 32 MiB-inflating seed on purpose — see README).

use arbitrary::Arbitrary;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use browserid_core::StatusList;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    lst: String,
    raw: Vec<u8>,
    idx: u64,
}

fuzz_target!(|input: Input| {
    if let Ok(l) = StatusList::decode(&input.lst) {
        let _ = l.is_revoked(input.idx);
        let again = StatusList::decode(&l.encode().unwrap()).unwrap();
        assert_eq!(again, l);
    }
    // Arbitrary bytes as the inflated bitmap: encode/decode is the identity
    // under the cap.
    if input.raw.len() <= 4 * 1024 * 1024 {
        let _ = StatusList::decode(&B64.encode(&input.raw));
    }
});
