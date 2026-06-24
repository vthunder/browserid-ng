# Vendored `sbo-wasm` (generated — do not edit)

These files are the browser build of the SBO serialization kit, copied verbatim
from the SBO repo. The agent loads them to build **canonical SBO signing bytes
in-browser**, guaranteeing byte-parity with `sbo-core` (it is the same Rust),
so the typed signing extension never has to reimplement SBO's wire format.

- `sbo_wasm.js` — wasm-bindgen ES-module glue (default `init()` fetches the wasm)
- `sbo_wasm_bg.wasm` — the compiled module (~150 KB, release + wasm-opt)

## Regenerate

From the SBO repo:

```sh
cd reference_impl/sbo-wasm
./build-web.sh                      # → pkg/
cp pkg/sbo_wasm.js pkg/sbo_wasm_bg.wasm \
   <browserid-ng>/browserid-broker/static/common/js/sbo-wasm/
```

Exports used by the agent (`common/js/sbo-sign.js`): `signingBytes(spec)`,
`assembleWire(spec, sigHex)`, `objectHash(wire)`, and the `payload*` builders.
