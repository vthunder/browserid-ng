# Fuzz targets (security audit 2026-11, WS3)

cargo-fuzz (libFuzzer + ASAN) targets for every wire parser in the Rust
tree. Standalone workspace: nothing here is built by `cargo build
--workspace`, CI, or the Dockerfile.

| target | exercises |
|---|---|
| `jws_parse` | every compact-serialization parser (`DeviceCert`, `AccessCert`, `AccessRequest`, `Warrant`, `Assertion`, `StatusListToken`, `AccessPresentation`, `RecordBundle`) plus `verify_at` / `validate` on whatever parses |
| `claims_json` | arbitrary JSON claim sets signed under fixture keys → typed parsers, `validate_claims`, binding deserialization, the verifier |
| `scope_parse` | `ScopeEntry` / `Cap` JSON, `parse_money_minor`, `parse_iso_duration_secs`, the stricter-wins order (reflexive, antisymmetric on projections) |
| `identity` | `identity_eq`, `grantee_covers`, `normalize_domain` idempotence, `HolderMatcher::matches`, and `identity_matches` against a reference re-implementation |
| `dns_txt` | `DnsRecord::parse` on lossy-decoded bytes; `Ok` ⇒ key comes from the `public-key=` field (July M5 class) |
| `status_list` | `StatusList::decode` / `encode` / `is_revoked` |
| `request_kind_json` | the five `docs/specs/request-kinds/*.json` schemas via `jsonschema`, the registrar's `WarrantRequestBody` / `RecordRequestBody`, and the warrant.json ↔ registrar differential |

## Running

```sh
rustup toolchain install nightly --profile minimal   # once
cargo install cargo-fuzz                             # once
make fuzz-smoke                                      # 60 s per target
FUZZ_SECS=900 scripts/fuzz-smoke.sh jws_parse        # one target, longer
cd fuzz && cargo +nightly fuzz run claims_json corpus/claims_json seeds/claims_json -- -max_total_time=3600 -jobs=4 -workers=4
```

On the dev box wrap every command in `ssh localtest '…'` (macOS Gatekeeper
stalls fresh binaries). `cargo +nightly fuzz list` prints the targets;
`cargo +nightly fuzz fmt <target> <artifact>` pretty-prints an
`Arbitrary` input from a crash file.

Layout: `seeds/<target>/` is the committed seed corpus (regenerate with
`cargo run --release --bin gen_seeds`); `corpus/<target>/` is the growing
run corpus and `artifacts/<target>/` holds crashes — both ignored. A crash
that reproduces gets minimised (`cargo +nightly fuzz tmin`), copied into
`seeds/<target>/crash-<id>`, and an `#[ignore]`d regression test in the
owning crate.

Known, guarded findings: `jws_parse` and `claims_json` skip the
`Constraints::check` / `is_fresh*` calls on inputs that would overflow
`exp − iat` or `iat + ttl` (W3-1 / W3-2 in the WS3 report); remove the
guards when those land. `seeds/status_list/bomb_32mib` inflates to 32 MiB
on purpose (W6-3): it stays under the 2 GiB RSS limit, so the run does not
crash on it, but it keeps the inflate-before-cap path hot.
