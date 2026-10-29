//! AES-256-GCM field sealing for the keys product. Data keys come from a Worker
//! secret keyring (same shape as WAYPOST_ENCRYPTION_KEYS); new writes use the
//! active key ID and older key IDs stay readable until every field is rewritten.
use crate::error::{Error, Result};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

const AAD_LABEL: &str = "keyenv-remote-field-v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringConfig {
    active: String,
    keys: BTreeMap<String, String>,
}

pub(crate) struct Keyring {
    active: String,
    keys: BTreeMap<String, Zeroizing<[u8; 32]>>,
}

pub(crate) struct Sealed {
    pub kid: String,
    pub nonce: String,
    pub ciphertext: String,
}

impl Keyring {
    pub(crate) fn parse(input: &str) -> Result<Self> {
        let invalid = || Error::invalid("Invalid keys data keyring.");
        let config: KeyringConfig = serde_json::from_str(input).map_err(|_| invalid())?;
        if config.keys.is_empty()
            || config.keys.len() > 8
            || !config.keys.contains_key(&config.active)
        {
            return Err(invalid());
        }
        let mut keys = BTreeMap::new();
        for (id, secret) in config.keys {
            if id.is_empty()
                || id.len() > 32
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(invalid());
            }
            let bytes = Zeroizing::new(hex::decode(secret).map_err(|_| invalid())?);
            let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| invalid())?;
            keys.insert(id, Zeroizing::new(key));
        }
        Ok(Self {
            active: config.active,
            keys,
        })
    }
    /// The ciphertext is bound to account, entry, field and key ID: a row moved
    /// to another entry, field or account does not decrypt.
    fn aad(account: &str, entry: &str, field: &str, kid: &str) -> Result<Vec<u8>> {
        crate::json::canonical(&json!([AAD_LABEL, account, entry, field, kid]))
    }
    pub(crate) fn seal(
        &self,
        account: &str,
        entry: &str,
        field: &str,
        value: &str,
    ) -> Result<Sealed> {
        let key = self
            .keys
            .get(&self.active)
            .ok_or_else(|| Error::internal("keys data key unavailable"))?;
        let cipher =
            Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| Error::internal("keys cipher"))?;
        let nonce = crate::service::random_bytes::<12>()?;
        let aad = Self::aad(account, entry, field, &self.active)?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: value.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| Error::internal("keys encryption"))?;
        Ok(Sealed {
            kid: self.active.clone(),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        })
    }
    pub(crate) fn open(
        &self,
        account: &str,
        entry: &str,
        field: &str,
        sealed: &Sealed,
    ) -> Result<Zeroizing<String>> {
        let failed = || Error::internal("keys decryption");
        let key = self.keys.get(&sealed.kid).ok_or_else(failed)?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| failed())?;
        let nonce = URL_SAFE_NO_PAD
            .decode(&sealed.nonce)
            .map_err(|_| failed())?;
        if nonce.len() != 12 {
            return Err(failed());
        }
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&sealed.ciphertext)
            .map_err(|_| failed())?;
        let aad = Self::aad(account, entry, field, &sealed.kid)?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| failed())?,
        );
        Ok(Zeroizing::new(
            String::from_utf8(plain.to_vec()).map_err(|_| failed())?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const K1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const K2: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    #[test]
    fn sealing_binds_context_and_supports_rotation() {
        let old = Keyring::parse(&format!(r#"{{"active":"k1","keys":{{"k1":"{K1}"}}}}"#)).unwrap();
        let sealed = old.seal("acct", "entry", "TOKEN", "s3cr3t").unwrap();
        assert_eq!(sealed.kid, "k1");
        assert!(!sealed.ciphertext.contains("s3cr3t"));
        assert_eq!(
            *old.open("acct", "entry", "TOKEN", &sealed).unwrap(),
            "s3cr3t"
        );
        for (a, e, f) in [
            ("other", "entry", "TOKEN"),
            ("acct", "other", "TOKEN"),
            ("acct", "entry", "OTHER"),
        ] {
            assert!(old.open(a, e, f, &sealed).is_err());
        }
        let tampered = Sealed {
            kid: "k1".into(),
            nonce: sealed.nonce.clone(),
            // Flip one decoded byte so the tamper never coincides with the original.
            ciphertext: {
                let mut bytes = URL_SAFE_NO_PAD.decode(&sealed.ciphertext).unwrap();
                bytes[0] ^= 1;
                URL_SAFE_NO_PAD.encode(bytes)
            },
        };
        assert!(old.open("acct", "entry", "TOKEN", &tampered).is_err());
        // Rotation: k2 is active for new writes, k1 still opens old rows.
        let rotated = Keyring::parse(&format!(
            r#"{{"active":"k2","keys":{{"k1":"{K1}","k2":"{K2}"}}}}"#
        ))
        .unwrap();
        assert_eq!(
            *rotated.open("acct", "entry", "TOKEN", &sealed).unwrap(),
            "s3cr3t"
        );
        assert_eq!(
            rotated.seal("acct", "entry", "TOKEN", "v").unwrap().kid,
            "k2"
        );
        // Relabelling the key ID does not open the row.
        let relabelled = Sealed {
            kid: "k2".into(),
            nonce: sealed.nonce.clone(),
            ciphertext: sealed.ciphertext.clone(),
        };
        assert!(rotated.open("acct", "entry", "TOKEN", &relabelled).is_err());
        let dropped =
            Keyring::parse(&format!(r#"{{"active":"k2","keys":{{"k2":"{K2}"}}}}"#)).unwrap();
        assert!(dropped.open("acct", "entry", "TOKEN", &sealed).is_err());
    }

    #[test]
    fn keyring_rejects_bad_configuration() {
        for bad in [
            "{}".to_string(),
            format!(r#"{{"active":"k2","keys":{{"k1":"{K1}"}}}}"#),
            r#"{"active":"k1","keys":{"k1":"abcd"}}"#.to_string(),
            format!(r#"{{"active":"k 1","keys":{{"k 1":"{K1}"}}}}"#),
            format!(r#"{{"active":"k1","keys":{{"k1":"{K1}"}},"extra":1}}"#),
        ] {
            assert!(Keyring::parse(&bad).is_err(), "{bad}");
        }
    }
}
