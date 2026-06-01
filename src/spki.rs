//! Minimal hand-written DER assembly for SubjectPublicKeyInfo. Used
//! by encoder.import-object to wrap a foreign keymgmt's exported
//! public-key params into SPKI bytes that encode.encode then returns
//! verbatim. Mirrors pkcs11-bridge::spki but takes raw SEC1 point
//! bytes (no OCTET STRING wrapper) so the OSSL_PKEY_PARAM_PUB_KEY
//! payload from EVP_PKEY_get_octet_string_param fits without extra
//! marshalling.

/// id-ecPublicKey -- 1.2.840.10045.2.1
const OID_ID_EC_PUBLIC_KEY: &[u8] = &[
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
];
/// rsaEncryption -- 1.2.840.113549.1.1.1
const OID_RSA_ENCRYPTION: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
];
const DER_NULL: &[u8] = &[0x05, 0x00];

fn der_seq(content: &[u8]) -> Vec<u8> { wrap(0x30, content) }

fn der_bit_string(content: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(content.len() + 1);
    body.push(0x00);
    body.extend_from_slice(content);
    wrap(0x03, &body)
}

fn der_integer(big_endian: &[u8]) -> Vec<u8> {
    let mut start = 0;
    while start + 1 < big_endian.len() && big_endian[start] == 0 { start += 1; }
    let trimmed = &big_endian[start..];
    let mut body = Vec::with_capacity(trimmed.len() + 1);
    if !trimmed.is_empty() && trimmed[0] & 0x80 != 0 { body.push(0x00); }
    body.extend_from_slice(trimmed);
    wrap(0x02, &body)
}

fn wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81); out.push(len as u8);
    } else if len < 0x10000 {
        out.push(0x82);
        out.push((len >> 8) as u8); out.push(len as u8);
    } else if len < 0x1000000 {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >>  8) as u8);
        out.push(len as u8);
    } else {
        out.push(0x84);
        out.push((len >> 24) as u8);
        out.push((len >> 16) as u8);
        out.push((len >>  8) as u8);
        out.push(len as u8);
    }
    out.extend_from_slice(content);
    out
}

/// DER OID for the named EC curves OpenSSL exports via the "group"
/// OSSL_PARAM. Returns None for curves we don't handle here -- the
/// caller should error out rather than silently producing garbage.
pub fn ec_curve_oid_der(name: &str) -> Option<&'static [u8]> {
    match name {
        // prime256v1 / P-256 / secp256r1 -- 1.2.840.10045.3.1.7
        "prime256v1" | "P-256" | "secp256r1" =>
            Some(&[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
        // secp384r1 / P-384 -- 1.3.132.0.34
        "secp384r1" | "P-384" =>
            Some(&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]),
        // secp521r1 / P-521 -- 1.3.132.0.35
        "secp521r1" | "P-521" =>
            Some(&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]),
        _ => None,
    }
}

/// Build an EC SubjectPublicKeyInfo from a curve name + raw SEC1
/// uncompressed point (`0x04 || X || Y`).
pub fn build_ec_spki(curve: &str, sec1_point: &[u8]) -> Result<Vec<u8>, &'static str> {
    let oid = ec_curve_oid_der(curve).ok_or("unsupported EC curve for SPKI")?;
    let mut alg_id = Vec::with_capacity(OID_ID_EC_PUBLIC_KEY.len() + oid.len());
    alg_id.extend_from_slice(OID_ID_EC_PUBLIC_KEY);
    alg_id.extend_from_slice(oid);
    let alg = der_seq(&alg_id);
    let bits = der_bit_string(sec1_point);
    let mut spki = Vec::with_capacity(alg.len() + bits.len());
    spki.extend_from_slice(&alg);
    spki.extend_from_slice(&bits);
    Ok(der_seq(&spki))
}

/// Build an RSA SubjectPublicKeyInfo from raw big-endian modulus +
/// public exponent. Both inputs are positive bytes (no DER INTEGER
/// header); der_integer handles canonicalisation.
pub fn build_rsa_spki(modulus: &[u8], public_exponent: &[u8]) -> Vec<u8> {
    let m = der_integer(modulus);
    let e = der_integer(public_exponent);
    let mut rsa_pub = Vec::with_capacity(m.len() + e.len());
    rsa_pub.extend_from_slice(&m);
    rsa_pub.extend_from_slice(&e);
    let rsa_pub_seq = der_seq(&rsa_pub);

    let mut alg_id = Vec::with_capacity(OID_RSA_ENCRYPTION.len() + DER_NULL.len());
    alg_id.extend_from_slice(OID_RSA_ENCRYPTION);
    alg_id.extend_from_slice(DER_NULL);
    let alg = der_seq(&alg_id);

    let bits = der_bit_string(&rsa_pub_seq);

    let mut spki = Vec::with_capacity(alg.len() + bits.len());
    spki.extend_from_slice(&alg);
    spki.extend_from_slice(&bits);
    der_seq(&spki)
}
