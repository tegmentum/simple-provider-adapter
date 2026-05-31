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
            prov::Operation::Keymgmt => (
                vec![prov::OsslAlgorithm {
                    algorithm_names: "EC".into(),
                    property_definition: "provider=wit-bridge".into(),
                    description: Some("EC keymgmt via wit-bridge".into()),
                }], false),
            prov::Operation::Signature => (
                vec![prov::OsslAlgorithm {
                    algorithm_names: "ECDSA".into(),
                    property_definition: "provider=wit-bridge".into(),
                    description: Some("ECDSA via wit-bridge".into()),
                }], false),
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
                // Bit size + max-signature-size depend on curve.
                let (bits, max_sig) = match info.curve.as_str() {
                    "P-256" => (256u32, 72u64),
                    "P-384" => (384, 104),
                    "P-521" => (521, 139),
                    _       => (256, 72),
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
        let encoded = match algo {
            Some(backend::KeyAlgorithm::Ec(_)) => spki_to_subject_public_key(&spki)?,
            // RSA OSSL_PARAM encoded-public-key is the raw RSAPublicKey
            // DER (the BIT STRING contents, same idea). Strip SPKI down.
            Some(backend::KeyAlgorithm::Rsa(_)) => spki_to_subject_public_key(&spki)?,
            // Ed25519/Ed448: raw public key, same shape as the SPKI
            // BIT STRING contents.
            _ => spki_to_subject_public_key(&spki)?,
        };
        Ok(vec![vec![km::OsslParam {
            key: "encoded-public-key".into(),
            value: pk::OsslParamValue::OctetString(encoded),
        }]])
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
    fn gettable_ctx_params() -> Vec<sig::OsslParamDescriptor> { Vec::new() }
    fn settable_ctx_params() -> Vec<sig::OsslParamDescriptor> { Vec::new() }
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
        // sign_init (vs digest_sign_init) is called when the caller
        // (EVP_PKEY_sign) is doing the hashing itself and handing
        // the bridge a digest. Default to Ecdsa(Raw) so the backend
        // picks the raw mech (CKM_ECDSA, not CKM_ECDSA_SHA256 -- the
        // latter would double-hash). If params explicitly set a
        // digest other than "raw" the caller is asking us to hash --
        // honor that (e.g. legacy ENGINE-style callers).
        let mech = if has_explicit_digest(&params) {
            backend::SignatureMechanism::Ecdsa(parse_digest_param(&params))
        } else {
            backend::SignatureMechanism::Ecdsa(backend::DigestAlgorithm::Raw)
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
        _params: Vec<sig::OsslParam>,
    ) -> Result<(), sig::PkeyError> {
        let keydata = key.get::<Keydata>();
        let uri = keydata.uri.borrow().clone();
        if uri.is_empty() {
            return Err(sig::PkeyError::InvalidState(
                "wit-bridge digest_sign_init: keydata is empty".into()));
        }
        let digest = md.as_deref().map(digest_name_to_backend)
            .unwrap_or(backend::DigestAlgorithm::Sha256);
        self.uri.replace(Some(uri));
        self.mech.replace(Some(backend::SignatureMechanism::Ecdsa(digest)));
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

export!(Component);
