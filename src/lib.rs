//! simple-provider-adapter — Layer-2 of the openssl-provider-wit
//! stack.
//!
//! Exports the full `openssl:provider-abi` and imports the narrow
//! `tegmentum:key-backend`. Most adapter methods are mechanical
//! translation between OpenSSL's `OSSL_PARAM` mechanism specs and
//! the backend's typed `signature-mechanism` / `cipher-mechanism`
//! variants.
//!
//! Phase 3.3 scope: advertise one algorithm pair (keymgmt "EC" +
//! signature "ECDSA"), wire keymgmt.load(uri) → backend.key(uri),
//! wire signature.sign-init/sign → backend.sign.

wit_bindgen::generate!({
    world: "adapter",
    path: "wit",
    generate_all,
});

use std::cell::RefCell;

use exports::openssl::{
    asym_cipher::asym_cipher as ac,
    keymgmt::keymgmt as km,
    pkey::pkey as pk,
    provider::provider as prov,
    signature::signature as sig,
};
use tegmentum::key_backend::key_backend as backend;

struct Component;

// =========================================================================
// Helpers — OSSL_PARAM ↔ backend types
// =========================================================================

fn parse_digest_param(params: &[pk::OsslParam]) -> backend::DigestAlgorithm {
    for p in params {
        if p.key == "digest" {
            if let pk::OsslParamValue::Utf8String(s) = &p.value {
                return digest_name_to_backend(s);
            }
        }
    }
    backend::DigestAlgorithm::Sha256
}

#[allow(dead_code)]
fn has_explicit_digest(params: &[pk::OsslParam]) -> bool {
    params.iter().any(|p| p.key == "digest")
}

fn digest_name_to_backend(s: &str) -> backend::DigestAlgorithm {
    let up = s.to_ascii_uppercase();
    let norm = up.replace('-', "").replace("SHA2", "SHA");
    match norm.as_str() {
        "SHA1"     => backend::DigestAlgorithm::Sha1,
        "SHA224"   => backend::DigestAlgorithm::Sha224,
        "SHA256"   => backend::DigestAlgorithm::Sha256,
        "SHA384"   => backend::DigestAlgorithm::Sha384,
        "SHA512"   => backend::DigestAlgorithm::Sha512,
        "SHA3S256" => backend::DigestAlgorithm::Sha3S256,
        "SHA3S384" => backend::DigestAlgorithm::Sha3S384,
        "SHA3S512" => backend::DigestAlgorithm::Sha3S512,
        _          => backend::DigestAlgorithm::Sha256,
    }
}

/// Strip a SubjectPublicKeyInfo (X.509 DER) down to the BIT STRING
/// contents -- the raw subject-public-key bytes that OSSL_PKEY_PARAM_
/// ENCODED_PUBLIC_KEY expects (SEC1 uncompressed point for EC, raw
/// 32-byte public key for Ed25519, RSAPublicKey DER for RSA).
fn spki_to_subject_public_key(spki: &[u8]) -> Result<Vec<u8>, km::PkeyError> {
    // SPKI = SEQUENCE { AlgorithmIdentifier(SEQUENCE), BIT STRING }.
    // Skip outer SEQUENCE header, skip AlgorithmIdentifier SEQUENCE,
    // then we're at the BIT STRING. Skip 0x03 tag + length + the
    // unused-bits 0x00 byte; return the rest.
    let (_outer, body) = strip_tag_length(spki, 0x30)
        .ok_or_else(|| km::PkeyError::Internal("SPKI: not a SEQUENCE".into()))?;
    // Inside body: AlgorithmIdentifier (SEQUENCE), then BIT STRING.
    let (alg_len, after_alg_hdr) = read_tag_length(body, 0x30)
        .ok_or_else(|| km::PkeyError::Internal("SPKI: missing AlgorithmIdentifier".into()))?;
    let after_alg = &after_alg_hdr[alg_len..];
    let (_bs_len, bit_string_body) = read_tag_length(after_alg, 0x03)
        .ok_or_else(|| km::PkeyError::Internal("SPKI: missing BIT STRING".into()))?;
    if bit_string_body.is_empty() {
        return Err(km::PkeyError::Internal("SPKI: empty BIT STRING".into()));
    }
    // First byte is unused-bits count; should be 0 for crypto pubkeys.
    Ok(bit_string_body[1..].to_vec())
}

/// Strip a DER tag+length+value, returning (full slice, body slice).
fn strip_tag_length(buf: &[u8], expected_tag: u8) -> Option<(&[u8], &[u8])> {
    let (len, body) = read_tag_length(buf, expected_tag)?;
    Some((&buf[..body.as_ptr() as usize - buf.as_ptr() as usize + len], &body[..len]))
}

/// Read DER tag + length header. Returns (body_len, body_slice).
fn read_tag_length(buf: &[u8], expected_tag: u8) -> Option<(usize, &[u8])> {
    if buf.len() < 2 || buf[0] != expected_tag { return None; }
    let (len, hdr) = if buf[1] & 0x80 == 0 {
        (buf[1] as usize, 2)
    } else {
        let nb = (buf[1] & 0x7f) as usize;
        if nb == 0 || buf.len() < 2 + nb { return None; }
        let mut v = 0usize;
        for i in 0..nb { v = (v << 8) | buf[2 + i] as usize; }
        (v, 2 + nb)
    };
    if buf.len() < hdr + len { return None; }
    Some((len, &buf[hdr..]))
}

fn backend_to_pkey(e: backend::BackendError) -> pk::PkeyError {
    use backend::BackendError as B;
    use pk::PkeyError as P;
    match e {
        B::KeyNotFound(s)           => P::InvalidKey(s),
        B::AlgorithmMismatch(s)     => P::InvalidArgument(s),
        B::MechanismNotSupported(s) => P::NotSupported(s),
        B::AuthenticationFailed(s)  => P::InvalidState(s),
        B::TransportError(s)        => P::BackendError(s),
        B::Internal(s)              => P::BackendError(s),
    }
}

// =========================================================================
// PROVIDER
// =========================================================================

impl prov::Guest for Component {
    fn gettable_params() -> Vec<prov::OsslParamDescriptor> { Vec::new() }
    fn get_params(_keys: Vec<String>) -> Result<Vec<prov::OsslParam>, prov::PkeyError> {
        Ok(Vec::new())
    }
    fn query_operation(op: prov::Operation) -> (Vec<prov::OsslAlgorithm>, bool) {
        match op {
            // Two keymgmts: openssl fetches by name, picks the
            // matching dispatch. The wit-bridge keydata + the
            // underlying URI resolution is shared -- the adapter
            // routes per-key by inspecting the cached algorithm.
            prov::Operation::Keymgmt => (vec![
                prov::OsslAlgorithm {
                    algorithm_names: "EC".into(),
                    property_definition: "provider=wit-bridge".into(),
                    description: Some("EC keymgmt via wit-bridge".into()),
                },
                prov::OsslAlgorithm {
                    algorithm_names: "RSA".into(),
                    property_definition: "provider=wit-bridge".into(),
                    description: Some("RSA keymgmt via wit-bridge".into()),
                },
            ], false),
            // Two signatures: "ECDSA" for EC keys, "RSA-PSS" for
            // RSA keys. Each gets its own settable_ctx_params on the
            // C side (just "digest" for ECDSA; digest + pad-mode +
            // mgf1-digest + saltlen for RSA-PSS).
            prov::Operation::Signature => (vec![
                prov::OsslAlgorithm {
                    algorithm_names: "ECDSA".into(),
                    property_definition: "provider=wit-bridge".into(),
                    description: Some("ECDSA via wit-bridge".into()),
                },
                prov::OsslAlgorithm {
                    algorithm_names: "RSA-PSS".into(),
                    property_definition: "provider=wit-bridge".into(),
                    description: Some("RSA-PSS via wit-bridge".into()),
                },
            ], false),
            _ => (Vec::new(), true),
        }
    }
    fn unquery_operation(_op: prov::Operation, _algorithms: Vec<prov::OsslAlgorithm>) {}
    fn get_reason_strings() -> Vec<prov::OsslReasonString> { Vec::new() }
    fn get_capabilities(_capability: String)
        -> Result<Vec<Vec<prov::OsslParam>>, prov::PkeyError> {
        Ok(Vec::new())
    }
    fn self_test() -> Result<(), prov::PkeyError> { Ok(()) }
    fn random_bytes(
        _which: prov::RandomSource, _n: u64, _strength: u32,
    ) -> Result<Vec<u8>, prov::PkeyError> {
        Err(prov::PkeyError::NotSupported("wit-bridge: no RNG".into()))
    }
}

// =========================================================================
// KEYMGMT
// =========================================================================

impl km::Guest for Component {
    type Keydata = Keydata;
    type GenContext = GenContext;

    /// For OSSL_OP_SIGNATURE, return the signature algorithm name
    /// OpenSSL should fetch -- "ECDSA" for our EC keymgmt. (This is
    /// NOT the keymgmt's name; it's the matching signature impl's
    /// name that openssl invokes EVP_SIGNATURE_fetch on after
    /// looking up our keymgmt.)
    fn query_operation_name(op: km::Operation) -> Option<String> {
        match op {
            km::Operation::Signature => Some("ECDSA".into()),
            km::Operation::Keyexch   => Some("ECDH".into()),
            _                         => None,
        }
    }

    fn gettable_params() -> Vec<km::OsslParamDescriptor> { Vec::new() }
    fn settable_params() -> Vec<km::OsslParamDescriptor> { Vec::new() }
    fn import_types(_s: km::KeySelection) -> Vec<km::OsslParamDescriptor> { Vec::new() }
    fn export_types(_s: km::KeySelection) -> Vec<km::OsslParamDescriptor> { Vec::new() }
    fn import_types_ex(_s: km::KeySelection) -> Vec<km::OsslParamDescriptor> { Vec::new() }
    fn export_types_ex(_s: km::KeySelection) -> Vec<km::OsslParamDescriptor> { Vec::new() }

    fn load(reference: Vec<u8>) -> Result<km::Keydata, km::PkeyError> {
        let uri = String::from_utf8(reference)
            .map_err(|_| km::PkeyError::InvalidArgument(
                "wit-bridge load: reference is not UTF-8".into()))?;
        let key = backend::Key::new(&uri);
        let algorithm = key.algorithm();
        Ok(km::Keydata::new(Keydata {
            uri: RefCell::new(uri),
            backend_key: RefCell::new(Some(key)),
            algorithm: RefCell::new(Some(algorithm)),
        }))
    }
    fn gen_init(
        _selection: km::KeySelection, _params: Vec<km::OsslParam>,
    ) -> Result<km::GenContext, km::PkeyError> {
        Err(km::PkeyError::NotSupported("wit-bridge: keygen not supported".into()))
    }
    fn gen_settable_params() -> Vec<km::OsslParamDescriptor> { Vec::new() }
    fn gen_gettable_params() -> Vec<km::OsslParamDescriptor> { Vec::new() }
}

/// Per-keydata state. Phase 3 stores the URI plus the constructed
/// backend Key. The URI doubles as the cheap identity key for the
/// SignatureContext to clone -- holding the Key resource directly in
/// SignatureContext would require dup which the backend may not
/// support.
struct Keydata {
    uri: RefCell<String>,
    backend_key: RefCell<Option<backend::Key>>,
    algorithm: RefCell<Option<backend::KeyAlgorithm>>,
}

impl km::GuestKeydata for Keydata {
    fn new() -> Self {
        Self {
            uri: RefCell::new(String::new()),
            backend_key: RefCell::new(None),
            algorithm: RefCell::new(None),
        }
    }
    /// Phase 3: surface the params OpenSSL's EVP layer reads during
    /// signature init -- "group" (curve name for EC), "bits" (key
    /// size), "max-size" (max signature size). Ignores `_keys` --
    /// returns the canonical set; OpenSSL picks the entries it wants.
    fn get_params(&self, _keys: Vec<String>)
        -> Result<Vec<km::OsslParam>, km::PkeyError> {
        let mut out = Vec::new();
        match self.algorithm.borrow().as_ref() {
            Some(backend::KeyAlgorithm::Ec(info)) => {
                out.push(km::OsslParam {
                    key: "group".into(),
                    value: pk::OsslParamValue::Utf8String(info.curve.clone()),
                });
                // EC point conversion format: openssl's TLS sigalg
                // codepath asks for this and trips on a downstream
                // OID lookup if missing -> "no shared cipher".
                out.push(km::OsslParam {
                    key: "point-format".into(),
                    value: pk::OsslParamValue::Utf8String("uncompressed".into()),
                });
                // EC encoding name (per OpenSSL EC keymgmt impl).
                out.push(km::OsslParam {
                    key: "encoding".into(),
                    value: pk::OsslParamValue::Utf8String("named_curve".into()),
                });
                // OSSL_PKEY_PARAM_EC_GROUP_CHECK: tell openssl we've
                // already validated the curve. Some TLS sigalg paths
                // skip the curve-name OBJ lookup if this is present.
                // Also publish the integer NID directly so the sigalg
                // check can match by NID rather than string -> avoids
                // OBJ_txt2obj("secp384r1") miss on builds where the
                // NIST alias table only knows the OID number.
                let nid: i64 = match info.curve.as_str() {
                    "prime256v1" | "P-256" => 415,  // NID_X9_62_prime256v1
                    "secp384r1"  | "P-384" => 715,  // NID_secp384r1
                    "secp521r1"  | "P-521" => 716,  // NID_secp521r1
                    _ => -1,
                };
                if nid > 0 {
                    out.push(km::OsslParam {
                        key: "group-nid".into(),
                        value: pk::OsslParamValue::Integer(nid),
                    });
                }
                // Bit size + max-signature-size depend on curve.
                let (bits, max_sig) = match info.curve.as_str() {
                    "P-256" | "prime256v1" => (256u32, 72u64),
                    "P-384" | "secp384r1"  => (384, 104),
                    "P-521" | "secp521r1"  => (521, 139),
                    _                      => (256, 72),
                };
                out.push(km::OsslParam {
                    key: "bits".into(),
                    value: pk::OsslParamValue::UnsignedInteger(bits as u64),
                });
                out.push(km::OsslParam {
                    key: "security-bits".into(),
                    value: pk::OsslParamValue::UnsignedInteger(bits as u64 / 2),
                });
                out.push(km::OsslParam {
                    key: "max-size".into(),
                    value: pk::OsslParamValue::UnsignedInteger(max_sig),
                });
                // SPKI-derived encoded public key (so EVP_PKEY-side
                // ops that need raw point bytes can find them).
                if let Some(key) = self.backend_key.borrow().as_ref() {
                    if let Ok(spki) = key.public_key_info() {
                        out.push(km::OsslParam {
                            key: "encoded-public-key".into(),
                            value: pk::OsslParamValue::OctetString(spki),
                        });
                    }
                }
            }
            Some(backend::KeyAlgorithm::Rsa(info)) => {
                out.push(km::OsslParam {
                    key: "bits".into(),
                    value: pk::OsslParamValue::UnsignedInteger(info.modulus_bits as u64),
                });
                out.push(km::OsslParam {
                    key: "max-size".into(),
                    value: pk::OsslParamValue::UnsignedInteger((info.modulus_bits / 8) as u64),
                });
            }
            _ => {}
        }
        Ok(out)
    }
    fn set_params(&self, _params: Vec<km::OsslParam>) -> Result<(), km::PkeyError> {
        Ok(())
    }
    fn has(&self, selection: km::KeySelection) -> bool {
        if self.backend_key.borrow().is_none() { return false; }
        let mask = km::KeySelection::PRIVATE_KEY | km::KeySelection::PUBLIC_KEY;
        selection.intersects(mask)
    }
    fn validate(
        &self, _selection: km::KeySelection, _level: km::ValidationLevel,
    ) -> Result<(), km::PkeyError> {
        Ok(())
    }
    fn match_(&self, other: km::KeydataBorrow<'_>, _selection: km::KeySelection) -> bool {
        let other = other.get::<Keydata>();
        *self.uri.borrow() == *other.uri.borrow()
    }
    fn import(
        &self, _selection: km::KeySelection, params: Vec<km::OsslParam>,
    ) -> Result<(), km::PkeyError> {
        // Look for the "wit-bridge-uri" OSSL_PARAM; if present, treat
        // its value as the URI for backend.Key::new. This lets the
        // openssl-wasm side use the standard EVP_PKEY_fromdata API
        // path (which routes through keymgmt.import) to construct a
        // bridge-backed key, without needing OSSL_STORE wiring.
        for p in &params {
            if p.key == "wit-bridge-uri" {
                let uri = match &p.value {
                    pk::OsslParamValue::Utf8String(s) => s.clone(),
                    pk::OsslParamValue::OctetString(b) => {
                        String::from_utf8(b.clone()).map_err(|_|
                            km::PkeyError::InvalidArgument(
                                "wit-bridge-uri octet-string is not UTF-8".into()))?
                    }
                    _ => return Err(km::PkeyError::InvalidArgument(
                        "wit-bridge-uri must be utf8-string or octet-string".into())),
                };
                let key = backend::Key::new(&uri);
                let algorithm = key.algorithm();
                // Mutate -- the resource was constructed empty by
                // keymgmt.keydata.constructor, this import call fills
                // it in.
                *self.backend_key.borrow_mut() = Some(key);
                *self.algorithm.borrow_mut()   = Some(algorithm);
                // SAFETY: `self.uri` is read-only after construction.
                // We can't mutate the String field directly (no
                // RefCell wrap), so use unsafe interior mutation via
                // pointer cast. Adapter is single-threaded; no race.
                // Alternative: wrap uri in RefCell too.
                *self.uri.borrow_mut() = uri;
                return Ok(());
            }
        }
        Err(km::PkeyError::NotSupported(
            "wit-bridge: import requires the `wit-bridge-uri` OSSL_PARAM".into()))
    }
    fn export(
        &self, selection: km::KeySelection,
    ) -> Result<Vec<Vec<km::OsslParam>>, km::PkeyError> {
        if selection.contains(km::KeySelection::PRIVATE_KEY) {
            return Err(km::PkeyError::NotSupported(
                "wit-bridge: private key cannot be extracted".into()));
        }
        let key = self.backend_key.borrow();
        let key = key.as_ref().ok_or_else(||
            km::PkeyError::InvalidState("keydata has no backend key".into()))?;
        let spki = key.public_key_info().map_err(backend_to_pkey)?;

        // OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY expects:
        //   - EC: the SEC1 uncompressed point (e.g. 65 bytes for P-256:
        //         0x04 || X || Y), NOT a SubjectPublicKeyInfo wrapper.
        //   - Ed25519/X25519: the raw 32-byte public key.
        //
        // The bridge's public_key_info() returns SPKI (most useful for
        // cert / chain construction); strip down to the BIT STRING
        // contents for the OSSL_PARAM. Adapter doesn't know the key
        // algorithm here directly; introspect algorithm cache.
        let algo = self.algorithm.borrow().clone();
        let encoded = spki_to_subject_public_key(&spki)?;
        let mut out = vec![
            // OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY: raw subject-public-key
            // bytes (SEC1 uncompressed point for EC, raw 32 bytes for
            // Ed25519, RSAPublicKey DER for RSA).
            km::OsslParam {
                key: "encoded-pub-key".into(),
                value: pk::OsslParamValue::OctetString(encoded.clone()),
            },
            // Some openssl call sites use "pub" (without the
            // "encoded-" prefix). Both names point at the same bytes.
            km::OsslParam {
                key: "pub".into(),
                value: pk::OsslParamValue::OctetString(encoded),
            },
        ];
        // EC keys additionally need the curve name -- without it
        // OpenSSL's EC keymgmt rejects fromdata / set_pubkey. The
        // i2d_PUBKEY encoder for SubjectPublicKeyInfo also needs
        // point-format + encoding alongside the bytes, or it trips
        // EC_R_INVALID_ENCODING decoding the SEC1 point.
        if let Some(backend::KeyAlgorithm::Ec(info)) = algo {
            out.push(km::OsslParam {
                key: "group".into(),
                value: pk::OsslParamValue::Utf8String(info.curve),
            });
            out.push(km::OsslParam {
                key: "point-format".into(),
                value: pk::OsslParamValue::Utf8String("uncompressed".into()),
            });
            out.push(km::OsslParam {
                key: "encoding".into(),
                value: pk::OsslParamValue::Utf8String("named_curve".into()),
            });
        }
        Ok(vec![out])
    }
    fn dup(&self, _selection: km::KeySelection)
        -> Result<km::Keydata, km::PkeyError> {
        let uri = self.uri.borrow().clone();
        let key = backend::Key::new(&uri);
        let algo = self.algorithm.borrow().clone();
        Ok(km::Keydata::new(Keydata {
            uri: RefCell::new(uri),
            backend_key: RefCell::new(Some(key)),
            algorithm: RefCell::new(algo),
        }))
    }
}

struct GenContext;
impl km::GuestGenContext for GenContext {
    fn set_template(&self, _t: km::KeydataBorrow<'_>) -> Result<(), km::PkeyError> {
        Err(km::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn set_params(&self, _params: Vec<km::OsslParam>) -> Result<(), km::PkeyError> {
        Err(km::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn get_params(&self, _keys: Vec<String>)
        -> Result<Vec<km::OsslParam>, km::PkeyError> {
        Err(km::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn gen(&self) -> Result<km::Keydata, km::PkeyError> {
        Err(km::PkeyError::NotSupported("phase-3 stub".into()))
    }
}

// =========================================================================
// SIGNATURE
// =========================================================================

impl sig::Guest for Component {
    type SignatureContext = SignatureContext;

    fn query_key_types() -> Vec<String> { vec!["EC".into()] }
    fn gettable_ctx_params() -> Vec<sig::OsslParamDescriptor> {
        // What can be read back via signature.get_ctx_params. The
        // legacy EVP_PKEY_CTX_ctrl translation layer (ctrl_params_
        // translate.c) refuses unknown params on the get side; same
        // shape as settable below.
        vec![
            sig::OsslParamDescriptor {
                key: "digest".into(),
                kind: pk::OsslParamKind::Utf8String,
            },
            sig::OsslParamDescriptor {
                key: "pad-mode".into(),
                kind: pk::OsslParamKind::Utf8String,
            },
            sig::OsslParamDescriptor {
                key: "algorithm-id".into(),
                kind: pk::OsslParamKind::OctetString,
            },
        ]
    }
    fn settable_ctx_params() -> Vec<sig::OsslParamDescriptor> {
        // ctrl_params_translate.c (legacy EVP_PKEY_CTX_set_signature_md
        // / set_rsa_padding / etc. -> OSSL_PARAM translation) raises
        // ERR_R_UNSUPPORTED when the destination's settable_ctx_params
        // doesn't advertise the key it's translating to. TLS's
        // CertVerify path goes through this, calling
        // EVP_PKEY_CTX_set_signature_md(md) which translates to
        // OSSL_PARAM "digest" -> our set_ctx_params.
        //
        // Phase 8a: enumerate the params TLS/X509 set during
        // sign-init. "digest" covers ECDSA + RSA; "pad-mode" +
        // "saltlen" cover RSA-PSS; "mgf1-digest" + "mgf1-properties"
        // for RSA-PSS / RSA-OAEP. List is over-broad on purpose --
        // our set_ctx_params accepts anything silently, so listing
        // extra keys doesn't hurt; it just keeps ctrl_params_
        // translate satisfied for any future caller.
        vec![
            sig::OsslParamDescriptor {
                key: "digest".into(),
                kind: pk::OsslParamKind::Utf8String,
            },
            sig::OsslParamDescriptor {
                key: "properties".into(),
                kind: pk::OsslParamKind::Utf8String,
            },
            sig::OsslParamDescriptor {
                key: "pad-mode".into(),
                kind: pk::OsslParamKind::Utf8String,
            },
            sig::OsslParamDescriptor {
                key: "mgf1-digest".into(),
                kind: pk::OsslParamKind::Utf8String,
            },
            sig::OsslParamDescriptor {
                key: "mgf1-properties".into(),
                kind: pk::OsslParamKind::Utf8String,
            },
            sig::OsslParamDescriptor {
                key: "saltlen".into(),
                kind: pk::OsslParamKind::Integer,
            },
        ]
    }
}

/// Per-signature-op state.
struct SignatureContext {
    uri: RefCell<Option<String>>,
    mech: RefCell<Option<backend::SignatureMechanism>>,
    update_buf: RefCell<Vec<u8>>,
}

impl sig::GuestSignatureContext for SignatureContext {
    fn new(_propq: Option<String>) -> Self {
        Self {
            uri: RefCell::new(None),
            mech: RefCell::new(None),
            update_buf: RefCell::new(Vec::new()),
        }
    }
    fn dup(&self) -> Result<sig::SignatureContext, sig::PkeyError> {
        Ok(sig::SignatureContext::new(Self {
            uri: RefCell::new(self.uri.borrow().clone()),
            mech: RefCell::new(self.mech.borrow().clone()),
            update_buf: RefCell::new(self.update_buf.borrow().clone()),
        }))
    }
    fn sign_init(
        &self, key: sig::KeydataBorrow<'_>, params: Vec<sig::OsslParam>,
    ) -> Result<(), sig::PkeyError> {
        let keydata = key.get::<Keydata>();
        let uri = keydata.uri.borrow().clone();
        if uri.is_empty() {
            return Err(sig::PkeyError::InvalidState(
                "wit-bridge sign_init: keydata is empty".into()));
        }
        // Pick mech based on the bound key's algorithm:
        //   EC keys  -> Ecdsa(Raw) (CKM_ECDSA, pre-hashed input)
        //   RSA keys -> RsaPss with default SHA-256 (overridable via
        //              the digest / mgf1-digest / saltlen OSSL_PARAMs;
        //              we ignore mgf1-digest != digest for now -- HSM
        //              tokens almost always require them equal).
        let algo = keydata.algorithm.borrow().clone();
        let mech = match algo {
            Some(backend::KeyAlgorithm::Rsa(_)) => {
                // RSA-PSS params: digest (OSSL_PARAM utf8 "digest"),
                // saltlen (int "saltlen"), mgf1-digest is ignored.
                let mut digest = backend::DigestAlgorithm::Sha256;
                let mut salt_len: u32 = 0; // 0 = use digest length
                for p in &params {
                    if p.key == "digest" {
                        if let pk::OsslParamValue::Utf8String(s) = &p.value {
                            digest = digest_name_to_backend(s);
                        }
                    } else if p.key == "saltlen" {
                        if let pk::OsslParamValue::Integer(n) = &p.value {
                            if *n >= 0 { salt_len = *n as u32; }
                        }
                    }
                }
                backend::SignatureMechanism::RsaPss(backend::RsaPssParams {
                    digest,
                    mgf1_digest: digest,
                    salt_len,
                })
            }
            // Default / EC path: pre-hashed input via CKM_ECDSA.
            _ => backend::SignatureMechanism::Ecdsa(backend::DigestAlgorithm::Raw),
        };
        self.uri.replace(Some(uri));
        self.mech.replace(Some(mech));
        Ok(())
    }
    fn sign(&self, tbs: Vec<u8>) -> Result<Vec<u8>, sig::PkeyError> {
        let uri = self.uri.borrow().clone().ok_or_else(||
            sig::PkeyError::InvalidState("sign called before sign_init".into()))?;
        let mech = self.mech.borrow().clone().ok_or_else(||
            sig::PkeyError::InvalidState("sign called before sign_init".into()))?;
        let key = backend::Key::new(&uri);
        key.sign(&tbs, mech).map_err(backend_to_pkey)
    }
    fn verify_init(
        &self, _key: sig::KeydataBorrow<'_>, _params: Vec<sig::OsslParam>,
    ) -> Result<(), sig::PkeyError> {
        Err(sig::PkeyError::NotSupported(
            "wit-bridge: verify uses openssl's own public-key path".into()))
    }
    fn verify(&self, _sig: Vec<u8>, _tbs: Vec<u8>) -> Result<(), sig::PkeyError> {
        Err(sig::PkeyError::NotSupported("wit-bridge: see verify_init".into()))
    }
    fn verify_recover_init(
        &self, _key: sig::KeydataBorrow<'_>, _params: Vec<sig::OsslParam>,
    ) -> Result<(), sig::PkeyError> {
        Err(sig::PkeyError::NotSupported("wit-bridge: verify_recover is RSA-only".into()))
    }
    fn verify_recover(&self, _sig: Vec<u8>) -> Result<Vec<u8>, sig::PkeyError> {
        Err(sig::PkeyError::NotSupported("wit-bridge: verify_recover is RSA-only".into()))
    }
    fn digest_sign_init(
        &self, md: Option<String>, key: sig::KeydataBorrow<'_>,
        params: Vec<sig::OsslParam>,
    ) -> Result<(), sig::PkeyError> {
        let keydata = key.get::<Keydata>();
        let uri = keydata.uri.borrow().clone();
        if uri.is_empty() {
            return Err(sig::PkeyError::InvalidState(
                "wit-bridge digest_sign_init: keydata is empty".into()));
        }
        let digest = md.as_deref().map(digest_name_to_backend)
            .unwrap_or(backend::DigestAlgorithm::Sha256);
        // Pick mech based on the bound key's algorithm. RSA keys
        // get RsaPss with the requested digest (and optional saltlen
        // from OSSL_PARAMs); EC keys keep the existing Ecdsa(digest)
        // path which routes to CKM_ECDSA_SHAxxx.
        let algo = keydata.algorithm.borrow().clone();
        let mech = match algo {
            Some(backend::KeyAlgorithm::Rsa(_)) => {
                let mut salt_len: u32 = 0;
                for p in &params {
                    if p.key == "saltlen" {
                        if let pk::OsslParamValue::Integer(n) = &p.value {
                            if *n >= 0 { salt_len = *n as u32; }
                        }
                    }
                }
                backend::SignatureMechanism::RsaPss(backend::RsaPssParams {
                    digest,
                    mgf1_digest: digest,
                    salt_len,
                })
            }
            _ => backend::SignatureMechanism::Ecdsa(digest),
        };
        self.uri.replace(Some(uri));
        self.mech.replace(Some(mech));
        self.update_buf.borrow_mut().clear();
        Ok(())
    }
    fn digest_sign_update(&self, data: Vec<u8>) -> Result<(), sig::PkeyError> {
        self.update_buf.borrow_mut().extend_from_slice(&data);
        Ok(())
    }
    fn digest_sign_final(&self) -> Result<Vec<u8>, sig::PkeyError> {
        let tbs = std::mem::take(&mut *self.update_buf.borrow_mut());
        self.sign(tbs)
    }
    fn digest_sign(&self, tbs: Vec<u8>) -> Result<Vec<u8>, sig::PkeyError> {
        self.sign(tbs)
    }
    fn digest_verify_init(
        &self, _md: Option<String>, _key: sig::KeydataBorrow<'_>,
        _params: Vec<sig::OsslParam>,
    ) -> Result<(), sig::PkeyError> {
        Err(sig::PkeyError::NotSupported("wit-bridge: see verify_init".into()))
    }
    fn digest_verify_update(&self, _data: Vec<u8>) -> Result<(), sig::PkeyError> {
        Err(sig::PkeyError::NotSupported("wit-bridge: see verify_init".into()))
    }
    fn digest_verify_final(&self, _sig: Vec<u8>) -> Result<(), sig::PkeyError> {
        Err(sig::PkeyError::NotSupported("wit-bridge: see verify_init".into()))
    }
    fn digest_verify(&self, _sig: Vec<u8>, _tbs: Vec<u8>) -> Result<(), sig::PkeyError> {
        Err(sig::PkeyError::NotSupported("wit-bridge: see verify_init".into()))
    }
    fn get_ctx_params(&self, _keys: Vec<String>)
        -> Result<Vec<sig::OsslParam>, sig::PkeyError> { Ok(Vec::new()) }
    fn set_ctx_params(&self, _params: Vec<sig::OsslParam>)
        -> Result<(), sig::PkeyError> { Ok(()) }
    fn get_ctx_md_params(&self, _keys: Vec<String>)
        -> Result<Vec<sig::OsslParam>, sig::PkeyError> { Ok(Vec::new()) }
    fn set_ctx_md_params(&self, _params: Vec<sig::OsslParam>)
        -> Result<(), sig::PkeyError> { Ok(()) }
    fn gettable_ctx_md_params(&self) -> Vec<sig::OsslParamDescriptor> { Vec::new() }
    fn settable_ctx_md_params(&self) -> Vec<sig::OsslParamDescriptor> { Vec::new() }
}

// =========================================================================
// ASYM-CIPHER (Phase 8 will wire for RSA decrypt)
// =========================================================================

impl ac::Guest for Component {
    type AsymCipherContext = AsymCipherContext;

    fn gettable_ctx_params() -> Vec<ac::OsslParamDescriptor> { Vec::new() }
    fn settable_ctx_params() -> Vec<ac::OsslParamDescriptor> { Vec::new() }
}

struct AsymCipherContext;
impl ac::GuestAsymCipherContext for AsymCipherContext {
    fn new() -> Self { Self }
    fn dup(&self) -> Result<ac::AsymCipherContext, ac::PkeyError> {
        Err(ac::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn encrypt_init(
        &self, _key: ac::KeydataBorrow<'_>, _params: Vec<ac::OsslParam>,
    ) -> Result<(), ac::PkeyError> {
        Err(ac::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn encrypt(&self, _plaintext: Vec<u8>) -> Result<Vec<u8>, ac::PkeyError> {
        Err(ac::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn decrypt_init(
        &self, _key: ac::KeydataBorrow<'_>, _params: Vec<ac::OsslParam>,
    ) -> Result<(), ac::PkeyError> {
        Err(ac::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn decrypt(&self, _ct: Vec<u8>) -> Result<Vec<u8>, ac::PkeyError> {
        Err(ac::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn get_ctx_params(&self, _keys: Vec<String>)
        -> Result<Vec<ac::OsslParam>, ac::PkeyError> { Ok(Vec::new()) }
    fn set_ctx_params(&self, _params: Vec<ac::OsslParam>)
        -> Result<(), ac::PkeyError> { Ok(()) }
}

// pkey holds only types now -- no Guest trait to implement.
// Reference the type module so wit-bindgen still pulls it into the
// canonical-ABI metadata.
#[allow(dead_code)]
type _PkeyOsslParam = pk::OsslParam;

// ---------------------------------------------------------------------------
// Phase 8: ENCODER + DECODER stub exports.
//
// provider.query-operation(encoder/decoder) returns no algorithms, so
// these resource methods are unreachable in practice. The stubs exist
// so wac plug can satisfy openssl-wasm's imports.
//
// Phase 8 follow-up (a Session 3 extension we punt for now): wire
// encode/decode through to tegmentum:key-backend when the backend
// supports public-key extraction.
// ---------------------------------------------------------------------------

use crate::exports::openssl::encoder::encoder as ex_encoder;
use crate::exports::openssl::decoder::decoder as ex_decoder;
use crate::exports::openssl::encoder::encoder::EncodeCtx as EncodeCtxRes;
use crate::exports::openssl::decoder::decoder::DecodeCtx as DecodeCtxRes;

pub struct StubEncodeCtx;
pub struct StubDecodeCtx;

impl ex_encoder::Guest for Component {
    type EncodeCtx = StubEncodeCtx;
    fn gettable_params() -> Vec<pk::OsslParamDescriptor> { Vec::new() }
    fn settable_ctx_params() -> Vec<pk::OsslParamDescriptor> { Vec::new() }
    fn does_selection(_s: pk::KeySelection) -> bool { false }
}

impl ex_encoder::GuestEncodeCtx for StubEncodeCtx {
    fn new() -> Self { StubEncodeCtx }
    fn get_params(&self) -> Result<Vec<pk::OsslParam>, pk::PkeyError> { Ok(Vec::new()) }
    fn set_ctx_params(&self, _p: Vec<pk::OsslParam>) -> Result<(), pk::PkeyError> { Ok(()) }
    fn import_object(&self, _s: pk::KeySelection, _p: Vec<pk::OsslParam>)
        -> Result<km::Keydata, pk::PkeyError>
    {
        Err(pk::PkeyError::NotSupported("encoder.import-object".into()))
    }
    fn encode(&self, _obj: ex_encoder::KeydataBorrow<'_>, _s: pk::KeySelection)
        -> Result<Vec<u8>, pk::PkeyError>
    {
        Err(pk::PkeyError::NotSupported("encoder.encode".into()))
    }
}

impl ex_decoder::Guest for Component {
    type DecodeCtx = StubDecodeCtx;
    fn gettable_params() -> Vec<pk::OsslParamDescriptor> { Vec::new() }
    fn settable_ctx_params() -> Vec<pk::OsslParamDescriptor> { Vec::new() }
    fn does_selection(_s: pk::KeySelection) -> bool { false }
}

impl ex_decoder::GuestDecodeCtx for StubDecodeCtx {
    fn new() -> Self { StubDecodeCtx }
    fn get_params(&self) -> Result<Vec<pk::OsslParam>, pk::PkeyError> { Ok(Vec::new()) }
    fn set_ctx_params(&self, _p: Vec<pk::OsslParam>) -> Result<(), pk::PkeyError> { Ok(()) }
    fn decode(&self, _i: Vec<u8>, _s: pk::KeySelection)
        -> Result<Vec<ex_decoder::DecodedObject>, pk::PkeyError>
    {
        Ok(Vec::new())  // empty result means "not recognised by this decoder"
    }
    fn export_object(&self, _obj: ex_decoder::KeydataBorrow<'_>)
        -> Result<Vec<pk::OsslParam>, pk::PkeyError>
    {
        Err(pk::PkeyError::NotSupported("decoder.export-object".into()))
    }
}

#[allow(dead_code)]
type _EncCtx = EncodeCtxRes;
#[allow(dead_code)]
type _DecCtx = DecodeCtxRes;

export!(Component);
