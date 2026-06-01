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

/// Reverse-lookup: DER-encoded curve OID → friendly name string.
/// Returns None for OIDs we don't recognise.
pub fn ec_oid_der_to_curve(oid: &[u8]) -> Option<&'static str> {
    match oid {
        [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] => Some("prime256v1"),
        [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]                   => Some("secp384r1"),
        [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23]                   => Some("secp521r1"),
        _ => None,
    }
}

/// What kind of public key a SubjectPublicKeyInfo carries.
pub enum SpkiPublicKey {
    Ec   { curve: &'static str, sec1_point: Vec<u8> },
    Rsa  { modulus: Vec<u8>,    public_exponent: Vec<u8> },
}

/// Parse a SubjectPublicKeyInfo DER blob. Recognises EC (with a
/// named curve we know about) and RSA. Returns a typed enum so the
/// caller can populate the matching keymgmt's OSSL_PARAM[] format.
pub fn parse_spki(spki: &[u8]) -> Result<SpkiPublicKey, &'static str> {
    let (_outer_len, body) = read_tag_length(spki, 0x30)
        .ok_or("SPKI: outer SEQUENCE missing")?;

    // AlgorithmIdentifier = SEQUENCE { OID, params }
    let (alg_len, alg_body) = read_tag_length(body, 0x30)
        .ok_or("SPKI: AlgorithmIdentifier missing")?;
    let after_alg = &body[alg_body.as_ptr() as usize - body.as_ptr() as usize + alg_len ..];

    // OID is first thing in alg_body
    let (oid_len, _) = read_tag_length(alg_body, 0x06)
        .ok_or("SPKI: AlgorithmIdentifier OID missing")?;
    let oid_total = oid_len + tag_header_len(alg_body);
    let oid = &alg_body[..oid_total];
    let alg_params = &alg_body[oid_total..];

    // BIT STRING after AlgorithmIdentifier
    let (_bs_len, bs_body) = read_tag_length(after_alg, 0x03)
        .ok_or("SPKI: BIT STRING missing")?;
    if bs_body.is_empty() { return Err("SPKI: empty BIT STRING"); }
    if bs_body[0] != 0    { return Err("SPKI: BIT STRING has nonzero unused-bits"); }
    let bits = &bs_body[1..];

    // OID match
    const OID_EC:  &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    const OID_RSA: &[u8] = &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

    if oid == OID_EC {
        let curve = ec_oid_der_to_curve(alg_params)
            .ok_or("SPKI: unrecognised EC curve OID")?;
        return Ok(SpkiPublicKey::Ec { curve, sec1_point: bits.to_vec() });
    }
    if oid == OID_RSA {
        // RSAPublicKey ::= SEQUENCE { modulus INTEGER, exponent INTEGER }
        let (_rsa_len, rsa_body) = read_tag_length(bits, 0x30)
            .ok_or("SPKI: RSAPublicKey SEQUENCE missing")?;
        let (n_len, n_body) = read_tag_length(rsa_body, 0x02)
            .ok_or("SPKI: RSA modulus INTEGER missing")?;
        let after_n = &rsa_body[n_body.as_ptr() as usize - rsa_body.as_ptr() as usize + n_len ..];
        let (e_len, e_body) = read_tag_length(after_n, 0x02)
            .ok_or("SPKI: RSA exponent INTEGER missing")?;
        // DER INTEGERs may have a leading 0x00 to keep the value
        // positive; strip it for the raw modulus / exponent bytes.
        let n = strip_leading_zero(&n_body[..n_len]);
        let e = strip_leading_zero(&e_body[..e_len]);
        return Ok(SpkiPublicKey::Rsa {
            modulus: n.to_vec(),
            public_exponent: e.to_vec(),
        });
    }
    Err("SPKI: unsupported algorithm OID")
}

fn strip_leading_zero(b: &[u8]) -> &[u8] {
    if b.len() > 1 && b[0] == 0 { &b[1..] } else { b }
}

fn tag_header_len(buf: &[u8]) -> usize {
    if buf.len() < 2 { return 0; }
    if buf[1] & 0x80 == 0 { 2 } else { 2 + (buf[1] & 0x7f) as usize }
}

/// Returns `(body_len, body_slice)` where body_slice is EXACTLY
/// body_len bytes (not the rest of buf). The redundant length is
/// kept for callers that need to walk past the TLV to the next
/// sibling — they recover the after-slice via &buf[hdr_len+body_len..].
fn read_tag_length(buf: &[u8], expected_tag: u8) -> Option<(usize, &[u8])> {
    if buf.len() < 2 || buf[0] != expected_tag { return None; }
    let (len, hdr) = if buf[1] & 0x80 == 0 {
        (buf[1] as usize, 2usize)
    } else {
        let nb = (buf[1] & 0x7f) as usize;
        if nb == 0 || buf.len() < 2 + nb { return None; }
        let mut v = 0usize;
        for i in 0..nb { v = (v << 8) | buf[2 + i] as usize; }
        (v, 2 + nb)
    };
    if buf.len() < hdr + len { return None; }
    Some((len, &buf[hdr..hdr + len]))
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
