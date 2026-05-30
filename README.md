simple-provider-adapter
=======================

Layer 2 of the openssl-provider-wit stack. A Rust wasm component
that exports the full `openssl:provider-abi` and imports the narrow
`tegmentum:key-backend`.

  openssl-wasm
    ↓ openssl:provider-abi (5 interfaces, 120 funcs)
  simple-provider-adapter         ← THIS COMPONENT
    ↓ tegmentum:key-backend (sign/verify/decrypt/derive)
  <backend>     ← pkcs11-bridge / stub / webauthn-adapter / ...

The adapter handles all the OSSL_PARAM marshalling, mechanism
translation, and resource lifecycle so a typical backend only has
to implement 7 methods on the `key` resource.

Status
------

**Phase 3.2 (scaffold)** — All 5 Guest impls present; every method
either returns an empty list or `pkey-error::not-supported`. The
component builds (`cargo build --release --target wasm32-wasip2`),
validates, and wac-composes cleanly into openssl-wasm. The existing
openssl-wasm TLS test suite passes against the composed component.

**Phase 3.3 (next)** — Wire `provider.query-operation` to advertise
one algorithm, fill in `keymgmt` and `signature` for that algorithm,
start calling out to the imported `tegmentum:key-backend`.

Build
-----

```
cargo build --release --target wasm32-wasip2
ls target/wasm32-wasip2/release/simple_provider_adapter.wasm

# Compose into openssl-wasm
wac plug ~/git/openssl-wasm/build/openssl-component.wasm \
    --plug target/wasm32-wasip2/release/simple_provider_adapter.wasm \
    -o /tmp/openssl-with-adapter.wasm
```

Toolchain pin
-------------

`wit-bindgen 0.44`. Newer wit-bindgen-rt versions aren't published
to crates.io yet (only the CLI is at 0.48). The WIT interfaces avoid
identifier shapes that 0.44 trips on (no digit immediately after `-`
in an enum variant -- "sha2-256" rejected; "sha256" fine).
