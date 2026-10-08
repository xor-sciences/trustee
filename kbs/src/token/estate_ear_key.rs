// Translate Veraison's authenticated key-attestation SPKI into the existing
// KBS JWE key type. The caller authenticates the JWT and evaluates resource
// policy first. This module does not appraise evidence or grant authorization.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use kbs_types::TeePubKey;
use p256::{pkcs8::DecodePublicKey, PublicKey};
use rsa::{traits::PublicKeyParts, RsaPublicKey};
use serde::Deserialize;
use serde_json::Value;

use super::{Error, Result};

const KEY_SUFFIX: &str = "/ear.veraison.key-attestation/akpub";

pub(super) fn extract(path: &str, value: &Value) -> Result<TeePubKey> {
    if !path.ends_with(KEY_SUFFIX) {
        return TeePubKey::deserialize(value).map_err(|_| Error::TeePubKeyParseFailed);
    }
    // Only a setup-selected submodule's key is consumed. Never scan submods or
    // fall back to a different key when the selected claim is malformed.
    let encoded = value.as_str().ok_or(Error::TeePubKeyParseFailed)?;
    if encoded.is_empty() || encoded.len() > 4096 {
        return Err(Error::TeePubKeyParseFailed);
    }
    let der = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Error::TeePubKeyParseFailed)?;
    if let Ok(key) = PublicKey::from_public_key_der(&der) {
        let point = p256::EncodedPoint::from(key);
        let x = point.x().ok_or(Error::TeePubKeyParseFailed)?;
        let y = point.y().ok_or(Error::TeePubKeyParseFailed)?;
        return Ok(TeePubKey::EC {
            crv: "P-256".into(),
            alg: "ECDH-ES+A256KW".into(),
            x: URL_SAFE_NO_PAD.encode(x),
            y: URL_SAFE_NO_PAD.encode(y),
        });
    }
    let key = RsaPublicKey::from_public_key_der(&der).map_err(|_| Error::TeePubKeyParseFailed)?;
    if !matches!(key.n().bits(), 2048 | 3072 | 4096) || key.e().to_bytes_be() != [1, 0, 1] {
        return Err(Error::TeePubKeyParseFailed);
    }
    Ok(TeePubKey::RSA {
        alg: "RSA-OAEP-256".into(),
        k_mod: URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
        k_exp: URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use josekit::jwe::{
        alg::{ecdh_es::EcdhEsJweAlgorithm::EcdhEsA256kw, rsaes::RsaesJweAlgorithm::RsaOaep256},
        JweContext,
    };
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use rsa::{rand_core::OsRng, RsaPrivateKey};
    use serde_json::json;

    const PATH: &str = "/submods/selected/ear.veraison.key-attestation/akpub";

    fn claim(key: &p256::SecretKey) -> Value {
        json!(URL_SAFE_NO_PAD.encode(key.public_key().to_public_key_der().unwrap().as_bytes()))
    }

    #[test]
    fn recipient_can_decrypt_existing_kbs_jwe_and_unrelated_key_cannot() {
        let recipient = p256::SecretKey::random(&mut OsRng);
        let wrong = p256::SecretKey::random(&mut OsRng);
        let tee_key = extract(PATH, &claim(&recipient)).unwrap();
        let plaintext = b"synthetic resource for recipient interoperability";
        let response = crate::jwe::jwe(tee_key, plaintext.to_vec()).unwrap();
        let encoded = serde_json::to_string(&response).unwrap();
        let pem = recipient.to_pkcs8_pem(LineEnding::LF).unwrap();
        let decrypter = EcdhEsA256kw.decrypter_from_pem(pem.as_bytes()).unwrap();
        let (decoded, _) = JweContext::new()
            .deserialize_json(&encoded, &decrypter)
            .unwrap();
        assert_eq!(decoded, plaintext);
        let wrong_pem = wrong.to_pkcs8_pem(LineEnding::LF).unwrap();
        let wrong_decrypter = EcdhEsA256kw
            .decrypter_from_pem(wrong_pem.as_bytes())
            .unwrap();
        assert!(JweContext::new()
            .deserialize_json(&encoded, &wrong_decrypter)
            .is_err());
    }

    #[test]
    fn attested_rsa_recipient_decrypts_kbs_jwe_and_wrong_key_cannot() {
        let recipient = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let wrong = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let public = recipient.to_public_key().to_public_key_der().unwrap();
        let claim = json!(URL_SAFE_NO_PAD.encode(public.as_bytes()));
        let tee_key = extract(PATH, &claim).unwrap();
        let plaintext = b"synthetic attested recipient resource";
        let response = crate::jwe::jwe(tee_key, plaintext.to_vec()).unwrap();
        let encoded = serde_json::to_string(&response).unwrap();
        let pem = recipient.to_pkcs8_pem(LineEnding::LF).unwrap();
        let decrypter = RsaOaep256.decrypter_from_pem(pem.as_bytes()).unwrap();
        let (decoded, _) = JweContext::new()
            .deserialize_json(&encoded, &decrypter)
            .unwrap();
        assert_eq!(decoded, plaintext);
        let wrong_pem = wrong.to_pkcs8_pem(LineEnding::LF).unwrap();
        let wrong_decrypter = RsaOaep256.decrypter_from_pem(wrong_pem.as_bytes()).unwrap();
        assert!(JweContext::new()
            .deserialize_json(&encoded, &wrong_decrypter)
            .is_err());
        assert!(extract("/tee-pubkey", &claim).is_err());
        let weak = RsaPrivateKey::new(&mut OsRng, 1024).unwrap();
        let weak_public = weak.to_public_key().to_public_key_der().unwrap();
        assert!(extract(PATH, &json!(URL_SAFE_NO_PAD.encode(weak_public.as_bytes()))).is_err());
    }

    #[test]
    fn existing_structured_keys_preserved_and_spki_requires_explicit_pointer() {
        let key = p256::SecretKey::random(&mut OsRng);
        let spki = claim(&key);
        assert!(extract("/tee-pubkey", &spki).is_err());
        let tee_key = extract(PATH, &spki).unwrap();
        let structured = serde_json::to_value(&tee_key).unwrap();
        let roundtrip = extract("/tee-pubkey", &structured).unwrap();
        assert_eq!(serde_json::to_value(roundtrip).unwrap(), structured);
        assert!(extract(PATH, &structured).is_err());
    }

    #[test]
    fn malformed_private_and_unsupported_keys_refuse() {
        let key = p256::SecretKey::random(&mut OsRng);
        let private = key.to_pkcs8_der().unwrap();
        let other = p521::SecretKey::random(&mut OsRng);
        let other_der = other.public_key().to_public_key_der().unwrap();
        let mut trailing = key
            .public_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        trailing.push(0);
        for bad in [
            Value::Null,
            json!({}),
            json!(1),
            json!(""),
            json!("%%"),
            json!("A".repeat(4097)),
            json!(URL_SAFE_NO_PAD.encode(b"not DER")),
            json!(URL_SAFE_NO_PAD.encode(private.as_bytes())),
            json!(URL_SAFE_NO_PAD.encode(other_der.as_bytes())),
            json!(URL_SAFE_NO_PAD.encode(trailing)),
        ] {
            assert!(extract(PATH, &bad).is_err());
        }
    }
}
