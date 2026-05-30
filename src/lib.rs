//! simple-provider-adapter — Layer-2 of the openssl-provider-wit
//! stack.
//!
//! Exports the full `openssl:provider-abi` (5 interfaces, ~120 funcs)
//! and imports the narrow `tegmentum:key-backend`. Most adapter
//! methods are mechanical translation between OpenSSL's `OSSL_PARAM`
//! mechanism specs and the backend's typed `signature-mechanism` /
//! `cipher-mechanism` variants.
//!
//! Phase 3 scope: all interfaces stubbed so the component links;
//! Phase 3.3 fills in the keymgmt+signature paths for one algorithm.

wit_bindgen::generate!({
    world: "adapter",
    path: "wit",
    generate_all,
});

use exports::openssl::{
    asym_cipher::asym_cipher as ac,
    keymgmt::keymgmt as km,
    pkey::pkey as pk,
    provider::provider as prov,
    signature::signature as sig,
};

// `Component` is the single target type for every Guest impl that
// `export!` wires together. Resource-Guest impls live on per-resource
// structs and are reached via the associated `type Foo = MyFoo;`
// declarations on each interface's Guest impl.
struct Component;

// --- Provider ------------------------------------------------------------

impl prov::Guest for Component {
    fn gettable_params() -> Vec<prov::OsslParamDescriptor> { Vec::new() }
    fn get_params(_keys: Vec<String>) -> Result<Vec<prov::OsslParam>, prov::PkeyError> {
        Ok(Vec::new())
    }
    fn query_operation(_op: prov::Operation) -> (Vec<prov::OsslAlgorithm>, bool) {
        // Phase 3.3 stub: advertise nothing yet. Will be populated
        // when keymgmt/signature have working implementations.
        (Vec::new(), true)
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
        Err(prov::PkeyError::NotSupported(
            "simple-provider-adapter: no RNG (use the default provider)".into()))
    }
}

// --- keymgmt -------------------------------------------------------------

impl km::Guest for Component {
    type KeydataMethods = KeydataMethods;
    type GenContextMethods = GenContextMethods;

    fn query_operation_name(_op: km::Operation) -> Option<String> { None }
    fn gettable_params() -> Vec<km::OsslParamDescriptor> { Vec::new() }
    fn settable_params() -> Vec<km::OsslParamDescriptor> { Vec::new() }
    fn import_types(_s: km::KeySelection) -> Vec<km::OsslParamDescriptor> { Vec::new() }
    fn export_types(_s: km::KeySelection) -> Vec<km::OsslParamDescriptor> { Vec::new() }
    fn import_types_ex(_s: km::KeySelection) -> Vec<km::OsslParamDescriptor> { Vec::new() }
    fn export_types_ex(_s: km::KeySelection) -> Vec<km::OsslParamDescriptor> { Vec::new() }

    fn load(_reference: Vec<u8>) -> Result<km::Keydata, km::PkeyError> {
        Err(km::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn gen_init(
        _selection: km::KeySelection, _params: Vec<km::OsslParam>,
    ) -> Result<km::GenContext, km::PkeyError> {
        Err(km::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn gen_settable_params() -> Vec<km::OsslParamDescriptor> { Vec::new() }
    fn gen_gettable_params() -> Vec<km::OsslParamDescriptor> { Vec::new() }
}

struct KeydataMethods;

impl km::GuestKeydataMethods for KeydataMethods {
    fn new() -> Self { Self }
    fn get_params(&self, _keys: Vec<String>)
        -> Result<Vec<km::OsslParam>, km::PkeyError> {
        Err(km::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn set_params(&self, _params: Vec<km::OsslParam>) -> Result<(), km::PkeyError> {
        Err(km::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn has(&self, _selection: km::KeySelection) -> bool { false }
    fn validate(
        &self, _selection: km::KeySelection, _level: km::ValidationLevel,
    ) -> Result<(), km::PkeyError> {
        Err(km::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn match_(&self, _other: km::KeydataBorrow<'_>, _selection: km::KeySelection) -> bool {
        false
    }
    fn import(
        &self, _selection: km::KeySelection, _params: Vec<km::OsslParam>,
    ) -> Result<(), km::PkeyError> {
        Err(km::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn export(
        &self, _selection: km::KeySelection,
    ) -> Result<Vec<Vec<km::OsslParam>>, km::PkeyError> {
        Err(km::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn dup(&self, _selection: km::KeySelection)
        -> Result<km::Keydata, km::PkeyError> {
        Err(km::PkeyError::NotSupported("phase-3 stub".into()))
    }
}

struct GenContextMethods;

impl km::GuestGenContextMethods for GenContextMethods {
    fn set_template(&self, _tmpl: km::KeydataBorrow<'_>) -> Result<(), km::PkeyError> {
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

// --- signature -----------------------------------------------------------

impl sig::Guest for Component {
    type SignatureContextMethods = SignatureContextMethods;

    fn query_key_types() -> Vec<String> { Vec::new() }
    fn gettable_ctx_params() -> Vec<sig::OsslParamDescriptor> { Vec::new() }
    fn settable_ctx_params() -> Vec<sig::OsslParamDescriptor> { Vec::new() }
}

struct SignatureContextMethods;

impl sig::GuestSignatureContextMethods for SignatureContextMethods {
    fn new(_propq: Option<String>) -> Self { Self }
    fn dup(&self) -> Result<sig::SignatureContext, sig::PkeyError> {
        Err(sig::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn sign_init(
        &self, _key: sig::KeydataBorrow<'_>, _params: Vec<sig::OsslParam>,
    ) -> Result<(), sig::PkeyError> {
        Err(sig::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn sign(&self, _tbs: Vec<u8>) -> Result<Vec<u8>, sig::PkeyError> {
        Err(sig::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn verify_init(
        &self, _key: sig::KeydataBorrow<'_>, _params: Vec<sig::OsslParam>,
    ) -> Result<(), sig::PkeyError> {
        Err(sig::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn verify(&self, _sig: Vec<u8>, _tbs: Vec<u8>) -> Result<(), sig::PkeyError> {
        Err(sig::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn verify_recover_init(
        &self, _key: sig::KeydataBorrow<'_>, _params: Vec<sig::OsslParam>,
    ) -> Result<(), sig::PkeyError> {
        Err(sig::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn verify_recover(&self, _sig: Vec<u8>) -> Result<Vec<u8>, sig::PkeyError> {
        Err(sig::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn digest_sign_init(
        &self, _md: Option<String>, _key: sig::KeydataBorrow<'_>,
        _params: Vec<sig::OsslParam>,
    ) -> Result<(), sig::PkeyError> {
        Err(sig::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn digest_sign_update(&self, _data: Vec<u8>) -> Result<(), sig::PkeyError> {
        Err(sig::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn digest_sign_final(&self) -> Result<Vec<u8>, sig::PkeyError> {
        Err(sig::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn digest_sign(&self, _tbs: Vec<u8>) -> Result<Vec<u8>, sig::PkeyError> {
        Err(sig::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn digest_verify_init(
        &self, _md: Option<String>, _key: sig::KeydataBorrow<'_>,
        _params: Vec<sig::OsslParam>,
    ) -> Result<(), sig::PkeyError> {
        Err(sig::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn digest_verify_update(&self, _data: Vec<u8>) -> Result<(), sig::PkeyError> {
        Err(sig::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn digest_verify_final(&self, _sig: Vec<u8>) -> Result<(), sig::PkeyError> {
        Err(sig::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn digest_verify(&self, _sig: Vec<u8>, _tbs: Vec<u8>) -> Result<(), sig::PkeyError> {
        Err(sig::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn get_ctx_params(&self, _keys: Vec<String>)
        -> Result<Vec<sig::OsslParam>, sig::PkeyError> {
        Err(sig::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn set_ctx_params(&self, _params: Vec<sig::OsslParam>) -> Result<(), sig::PkeyError> {
        Err(sig::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn get_ctx_md_params(&self, _keys: Vec<String>)
        -> Result<Vec<sig::OsslParam>, sig::PkeyError> {
        Err(sig::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn set_ctx_md_params(&self, _params: Vec<sig::OsslParam>) -> Result<(), sig::PkeyError> {
        Err(sig::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn gettable_ctx_md_params(&self) -> Vec<sig::OsslParamDescriptor> { Vec::new() }
    fn settable_ctx_md_params(&self) -> Vec<sig::OsslParamDescriptor> { Vec::new() }
}

// --- asym-cipher ---------------------------------------------------------

impl ac::Guest for Component {
    type AsymCipherContextMethods = AsymCipherContextMethods;

    fn gettable_ctx_params() -> Vec<ac::OsslParamDescriptor> { Vec::new() }
    fn settable_ctx_params() -> Vec<ac::OsslParamDescriptor> { Vec::new() }
}

struct AsymCipherContextMethods;

impl ac::GuestAsymCipherContextMethods for AsymCipherContextMethods {
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
        -> Result<Vec<ac::OsslParam>, ac::PkeyError> {
        Err(ac::PkeyError::NotSupported("phase-3 stub".into()))
    }
    fn set_ctx_params(&self, _params: Vec<ac::OsslParam>) -> Result<(), ac::PkeyError> {
        Err(ac::PkeyError::NotSupported("phase-3 stub".into()))
    }
}

// --- pkey (just resources; no top-level methods) -------------------------

impl pk::Guest for Component {
    type Keydata = Keydata;
    type GenContext = GenContext;
    type SignatureContext = SignatureContextResource;
    type AsymCipherContext = AsymCipherContextResource;
}

struct Keydata;
impl pk::GuestKeydata for Keydata {}

struct GenContext;
impl pk::GuestGenContext for GenContext {}

struct SignatureContextResource;
impl pk::GuestSignatureContext for SignatureContextResource {}

struct AsymCipherContextResource;
impl pk::GuestAsymCipherContext for AsymCipherContextResource {}

export!(Component);
