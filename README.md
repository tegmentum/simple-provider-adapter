# simple-provider-adapter

Layer 2 of the [openssl-provider-wit](https://github.com/tegmentum/openssl-provider-wit) stack. A Rust wasm component that exports the full `openssl:provider-abi` (keymgmt + signature + asym-cipher + provider entry point + shared types) and imports the narrow `tegmentum:key-backend` so swappable Layer-3 backends (real HSMs, WebAuthn, software keys) can plug in without re-implementing the OpenSSL 3 dispatch glue.

## Where it fits

```
[OpenSSL 3 — openssl-wasm runtime]
        │
        ▼  openssl:provider-abi (5 interfaces, 120 funcs)
┌─────────────────────────┐
│ simple-provider-adapter │  ← THIS COMPONENT (Layer 2)
└────────────┬────────────┘
             │  tegmentum:key-backend (sign / verify / decrypt / derive)
             ▼
[backend]  pkcs11-bridge | stub | webauthn-adapter | webcrypto-adapter | ...
```

The adapter handles OSSL_PARAM marshalling, mechanism translation, and resource lifecycle so a typical Layer-3 backend implements ~7 methods on the `key` resource and nothing else.

## Algorithm coverage

`query-operation` advertises per-algorithm dispatch tables:

| Operation | Algorithms |
|---|---|
| `OSSL_OP_KEYMGMT` | EC, RSA |
| `OSSL_OP_SIGNATURE` | ECDSA, RSA-PSS |

ECDSA path is wired against an EC keymgmt (CKA_EC_PARAMS export); RSA-PSS path advertises pad-mode + mgf1-digest + saltlen via settable_ctx_params, with the backend receiving a `RsaPssParams` struct on sign_init.

For broader OPs (KDF, KEY_EXCHANGE, ENCODER/DECODER, KEM) see [openssl-provider-wit Phase 8 backfill](https://github.com/tegmentum/openssl-provider-wit/blob/main/README.md).

## Quick start

Build:
```sh
cargo build --target wasm32-wasip2 --release
```

Compose into openssl-wasm:
```sh
wac plug ~/git/openssl-wasm/build/openssl-component.wasm \
    --plug target/wasm32-wasip2/release/simple_provider_adapter.wasm \
    -o /tmp/openssl-with-adapter.wasm
```

For an end-to-end stack with a real HSM, see the [python-wasm wac compose manifest](https://github.com/tegmentum/python-wasm/blob/main/scripts/wit-bridge-compose.wac).

## Plug-order gotcha

When composing with [pkcs11-store-adapter](https://github.com/tegmentum/pkcs11-store-adapter), the store adapter MUST be plugged BEFORE simple-provider-adapter so its transitive `openssl:pkey/pkey` import is satisfied by simple's export. Reverse the order and you get a dangling import in the final wasm. The composition is captured correctly in python-wasm's compose script.

## Toolchain

`wit-bindgen 0.44`. The WIT interfaces avoid identifier shapes that 0.44 rejects (no digit immediately after `-` in enum variants — use `sha256`, not `sha2-256`).

## License

Apache-2.0.
