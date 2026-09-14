//! Maintained cryptographic primitives for the authenticated receiver protocol.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub(crate) fn valid_lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn authentication_value(key: &[u8; 32], domain: &[u8], payload: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts a 32-byte key");
    mac.update(domain);
    mac.update(payload);
    format!("sha256:{}", hex::encode(mac.finalize().into_bytes()))
}

pub(crate) fn opaque_hmac_handle(key: &[u8; 32], domain: &[u8], payload: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts a 32-byte key");
    mac.update(domain);
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

pub(crate) fn opaque_public_handle(domain: &[u8], payloads: &[&[u8]]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    for payload in payloads {
        digest.update(payload);
    }
    hex::encode(digest.finalize())
}

pub(crate) fn verify_authentication(
    key: &[u8; 32],
    domain: &[u8],
    payloads: &[&[u8]],
    authentication: &str,
) -> bool {
    let Some(encoded) = authentication.strip_prefix("sha256:") else {
        return false;
    };
    if !valid_lower_hex_32(encoded) {
        return false;
    }
    let Ok(candidate) = hex::decode(encoded) else {
        return false;
    };
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts a 32-byte key");
    mac.update(domain);
    for payload in payloads {
        mac.update(payload);
    }
    mac.verify_slice(&candidate).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentication_is_domain_separated_and_exact() {
        let key = [7_u8; 32];
        let value = authentication_value(&key, b"domain-a\0", b"payload");
        assert!(verify_authentication(
            &key,
            b"domain-a\0",
            &[b"payload"],
            &value
        ));
        assert!(!verify_authentication(
            &key,
            b"domain-b\0",
            &[b"payload"],
            &value
        ));
    }
}
