// Copyright 2026 Salesforce, Inc. All rights reserved.

//! Self-contained values that every replica can verify without shared storage.
//!
//! - Signed (`v1.<body>.<hmac>`): client IDs and `state`. Integrity only; the holder may read
//!   the contents, which are its own redirect URIs and state.
//! - Encrypted (`v1e.<nonce || ciphertext>`): wrapped IdP codes and refresh tokens.
//!   XChaCha20-Poly1305, so the holder can neither read nor alter the IdP value inside. Without
//!   this, a client could take the raw IdP token out and use it outside the gateway's checks.
//!
//! Both bind the value to its kind and carry an expiry.

use std::convert::TryInto;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const SIGNED_PREFIX: &str = "v1.";
const ENCRYPTED_PREFIX: &str = "v1e.";
const MAX_SEALED_LEN: usize = 8192;
const ENCRYPTION_KEY_LABEL: &[u8] = b"mcp-oauth-dcr-cimd/encryption-key/v1";

pub(crate) const NONCE_LEN: usize = 24;

pub(crate) const KIND_CLIENT: &str = "client";
pub(crate) const KIND_STATE: &str = "state";
pub(crate) const KIND_CODE: &str = "code";
pub(crate) const KIND_REFRESH: &str = "refresh";

#[derive(Debug, PartialEq)]
pub enum SealError {
    Malformed,
    BadSignature,
    WrongKind,
    Expired,
    Internal,
}

#[derive(Serialize)]
struct EnvelopeOut<'a, T> {
    k: &'a str,
    exp: u64,
    d: &'a T,
}

#[derive(Deserialize)]
struct EnvelopeIn<T> {
    k: String,
    exp: u64,
    d: T,
}

pub struct Sealer {
    mac_key: Vec<u8>,
    cipher: Option<XChaCha20Poly1305>,
}

impl Sealer {
    pub fn new(secret: &str) -> Self {
        // Separate key for encryption, derived from the secret (HMAC as a KDF).
        let cipher = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
            .ok()
            .map(|mut kdf| {
                kdf.update(ENCRYPTION_KEY_LABEL);
                kdf.finalize().into_bytes()
            })
            .and_then(|key| <XChaCha20Poly1305 as KeyInit>::new_from_slice(&key[..]).ok());
        Self {
            mac_key: secret.as_bytes().to_vec(),
            cipher,
        }
    }

    fn mac(&self, kind: &str, body: &str) -> Result<HmacSha256, SealError> {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&self.mac_key).map_err(|_| SealError::Internal)?;
        mac.update(kind.as_bytes());
        mac.update(b".");
        mac.update(body.as_bytes());
        Ok(mac)
    }

    /// Signs `data` under `kind`. `exp` is a Unix timestamp in seconds; 0 means it never expires.
    pub fn seal<T: Serialize>(&self, kind: &str, data: &T, exp: u64) -> Result<String, SealError> {
        let body = URL_SAFE_NO_PAD.encode(envelope(kind, data, exp)?);
        let tag = self.mac(kind, &body)?.finalize().into_bytes();
        Ok(format!(
            "{}{}.{}",
            SIGNED_PREFIX,
            body,
            URL_SAFE_NO_PAD.encode(tag)
        ))
    }

    /// Verifies and decodes a value signed under `kind`, rejecting it if expired at `now`.
    pub fn open<T: DeserializeOwned>(
        &self,
        kind: &str,
        sealed: &str,
        now: u64,
    ) -> Result<T, SealError> {
        if sealed.len() > MAX_SEALED_LEN {
            return Err(SealError::Malformed);
        }
        let rest = sealed
            .strip_prefix(SIGNED_PREFIX)
            .ok_or(SealError::Malformed)?;
        let (body, tag) = rest.split_once('.').ok_or(SealError::Malformed)?;
        let tag = URL_SAFE_NO_PAD
            .decode(tag)
            .map_err(|_| SealError::Malformed)?;
        self.mac(kind, body)?
            .verify_slice(&tag)
            .map_err(|_| SealError::BadSignature)?;
        let json = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| SealError::Malformed)?;
        open_envelope(kind, &json, now)
    }

    /// Encrypts `data` under `kind`. `nonce` must be fresh random bytes for every call.
    pub fn seal_encrypted<T: Serialize>(
        &self,
        kind: &str,
        data: &T,
        exp: u64,
        nonce: &[u8; NONCE_LEN],
    ) -> Result<String, SealError> {
        let cipher = self.cipher.as_ref().ok_or(SealError::Internal)?;
        let plaintext = envelope(kind, data, exp)?;
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(*nonce),
                Payload {
                    msg: &plaintext,
                    aad: kind.as_bytes(),
                },
            )
            .map_err(|_| SealError::Internal)?;
        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(nonce);
        out.extend_from_slice(&ciphertext);
        Ok(format!(
            "{}{}",
            ENCRYPTED_PREFIX,
            URL_SAFE_NO_PAD.encode(out)
        ))
    }

    /// Decrypts a value sealed with [`Sealer::seal_encrypted`] under `kind`.
    pub fn open_encrypted<T: DeserializeOwned>(
        &self,
        kind: &str,
        sealed: &str,
        now: u64,
    ) -> Result<T, SealError> {
        if sealed.len() > MAX_SEALED_LEN {
            return Err(SealError::Malformed);
        }
        let cipher = self.cipher.as_ref().ok_or(SealError::Internal)?;
        let rest = sealed
            .strip_prefix(ENCRYPTED_PREFIX)
            .ok_or(SealError::Malformed)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(rest)
            .map_err(|_| SealError::Malformed)?;
        if bytes.len() <= NONCE_LEN {
            return Err(SealError::Malformed);
        }
        let (nonce, ciphertext) = bytes.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| SealError::Malformed)?;
        let plaintext = cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: kind.as_bytes(),
                },
            )
            .map_err(|_| SealError::BadSignature)?;
        open_envelope(kind, &plaintext, now)
    }
}

fn envelope<T: Serialize>(kind: &str, data: &T, exp: u64) -> Result<Vec<u8>, SealError> {
    serde_json::to_vec(&EnvelopeOut {
        k: kind,
        exp,
        d: data,
    })
    .map_err(|_| SealError::Internal)
}

fn open_envelope<T: DeserializeOwned>(kind: &str, json: &[u8], now: u64) -> Result<T, SealError> {
    let envelope: EnvelopeIn<T> = serde_json::from_slice(json).map_err(|_| SealError::Malformed)?;
    if envelope.k != kind {
        return Err(SealError::WrongKind);
    }
    if envelope.exp != 0 && now >= envelope.exp {
        return Err(SealError::Expired);
    }
    Ok(envelope.d)
}

/// Short, stable fingerprint of a value (first 128 bits of SHA-256, base64url).
/// Binds state, codes and refresh tokens to a client without embedding the full client_id.
pub fn fingerprint(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    URL_SAFE_NO_PAD.encode(digest.get(..16).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Payload {
        a: String,
    }

    const NONCE: [u8; NONCE_LEN] = [7u8; NONCE_LEN];

    fn sealer() -> Sealer {
        Sealer::new("0123456789abcdef0123456789abcdef")
    }

    fn payload() -> Payload {
        Payload { a: "x".to_string() }
    }

    #[test]
    fn round_trips() {
        let sealed = sealer().seal(KIND_STATE, &payload(), 0).unwrap();
        assert!(sealed.starts_with("v1."));
        let opened: Payload = sealer().open(KIND_STATE, &sealed, 1_000).unwrap();
        assert_eq!(opened, payload());
    }

    #[test]
    fn rejects_other_kind() {
        let sealed = sealer().seal(KIND_STATE, &payload(), 0).unwrap();
        let result: Result<Payload, _> = sealer().open(KIND_CODE, &sealed, 0);
        assert_eq!(result.unwrap_err(), SealError::BadSignature);
    }

    #[test]
    fn rejects_other_key() {
        let sealed = sealer().seal(KIND_STATE, &payload(), 0).unwrap();
        let other = Sealer::new("ffffffffffffffffffffffffffffffff");
        let result: Result<Payload, _> = other.open(KIND_STATE, &sealed, 0);
        assert_eq!(result.unwrap_err(), SealError::BadSignature);
    }

    #[test]
    fn rejects_tampered_body() {
        let sealed = sealer().seal(KIND_STATE, &payload(), 0).unwrap();
        let forged = sealer()
            .seal(KIND_STATE, &Payload { a: "y".into() }, 0)
            .unwrap();
        let (_, sig) = sealed.rsplit_once('.').unwrap();
        let (forged_body, _) = forged.rsplit_once('.').unwrap();
        let tampered = format!("{}.{}", forged_body, sig);
        let result: Result<Payload, _> = sealer().open(KIND_STATE, &tampered, 0);
        assert_eq!(result.unwrap_err(), SealError::BadSignature);
    }

    #[test]
    fn expires() {
        let sealed = sealer().seal(KIND_CODE, &payload(), 100).unwrap();
        assert!(sealer().open::<Payload>(KIND_CODE, &sealed, 99).is_ok());
        assert_eq!(
            sealer()
                .open::<Payload>(KIND_CODE, &sealed, 100)
                .unwrap_err(),
            SealError::Expired
        );
    }

    #[test]
    fn rejects_garbage() {
        for input in [
            "",
            "v1.",
            "v1.abc",
            "v2.abc.def",
            "v1.!!!.???",
            "v1e.",
            "v1e.AAAA",
        ] {
            assert!(
                sealer().open::<Payload>(KIND_CODE, input, 0).is_err(),
                "{}",
                input
            );
            assert!(
                sealer()
                    .open_encrypted::<Payload>(KIND_CODE, input, 0)
                    .is_err(),
                "{}",
                input
            );
        }
    }

    #[test]
    fn encrypted_round_trip_hides_contents() {
        let secret = Payload {
            a: "idp-refresh-token-value".into(),
        };
        let sealed = sealer()
            .seal_encrypted(KIND_REFRESH, &secret, 0, &NONCE)
            .unwrap();
        assert!(sealed.starts_with("v1e."));
        let raw = URL_SAFE_NO_PAD
            .decode(sealed.strip_prefix("v1e.").unwrap())
            .unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("idp-refresh-token-value"));
        let opened: Payload = sealer().open_encrypted(KIND_REFRESH, &sealed, 0).unwrap();
        assert_eq!(opened, secret);
    }

    #[test]
    fn encrypted_rejects_tampering_kind_key_and_expiry() {
        let sealed = sealer()
            .seal_encrypted(KIND_CODE, &payload(), 100, &NONCE)
            .unwrap();
        assert_eq!(
            sealer()
                .open_encrypted::<Payload>(KIND_REFRESH, &sealed, 0)
                .unwrap_err(),
            SealError::BadSignature
        );
        let other = Sealer::new("ffffffffffffffffffffffffffffffff");
        assert!(other
            .open_encrypted::<Payload>(KIND_CODE, &sealed, 0)
            .is_err());
        assert_eq!(
            sealer()
                .open_encrypted::<Payload>(KIND_CODE, &sealed, 100)
                .unwrap_err(),
            SealError::Expired
        );

        let mut bytes = URL_SAFE_NO_PAD
            .decode(sealed.strip_prefix("v1e.").unwrap())
            .unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let tampered = format!("v1e.{}", URL_SAFE_NO_PAD.encode(bytes));
        assert_eq!(
            sealer()
                .open_encrypted::<Payload>(KIND_CODE, &tampered, 0)
                .unwrap_err(),
            SealError::BadSignature
        );

        // A signed value is not accepted where an encrypted one is expected, and vice versa.
        let signed = sealer().seal(KIND_CODE, &payload(), 0).unwrap();
        assert!(sealer()
            .open_encrypted::<Payload>(KIND_CODE, &signed, 0)
            .is_err());
        assert!(sealer().open::<Payload>(KIND_CODE, &sealed, 0).is_err());
    }

    #[test]
    fn fingerprint_is_stable_and_distinct() {
        assert_eq!(fingerprint("a"), fingerprint("a"));
        assert_ne!(fingerprint("a"), fingerprint("b"));
        assert_eq!(fingerprint("a").len(), 22);
    }
}
