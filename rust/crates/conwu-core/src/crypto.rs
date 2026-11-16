use anyhow::{Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::{
    PublicKey, SecretKey,
    ecdsa::{
        Signature, SigningKey, VerifyingKey,
        signature::{Signer, Verifier},
    },
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
};
use rand::{RngCore, rngs::OsRng};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub fn b64(bytes: impl AsRef<[u8]>) -> String {
    STANDARD.encode(bytes)
}
pub fn unb64(text: &str) -> Result<Vec<u8>> {
    Ok(STANDARD.decode(text)?)
}
pub fn random<const N: usize>() -> [u8; N] {
    let mut b = [0; N];
    OsRng.fill_bytes(&mut b);
    b
}
pub fn hash(bytes: impl AsRef<[u8]>) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
pub fn eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}
pub fn hkdf(secret: &[u8], salt: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(salt), secret)
        .expand(info, &mut *key)
        .expect("fixed HKDF output");
    key
}
pub fn mac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut h = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key");
    h.update(message);
    h.finalize().into_bytes().into()
}
pub fn new_private() -> Result<String> {
    Ok(b64(SecretKey::random(&mut OsRng)
        .to_pkcs8_der()?
        .as_bytes()))
}
pub fn public(private: &str) -> Result<String> {
    Ok(b64(SecretKey::from_pkcs8_der(&unb64(private)?)?
        .public_key()
        .to_public_key_der()?
        .as_bytes()))
}
pub fn valid_public(public: &str) -> Result<()> {
    ensure!(public.len() <= 180, "public key too large");
    PublicKey::from_public_key_der(&unb64(public)?)?;
    Ok(())
}
pub fn exchange(private: &str, public: &str) -> Result<Zeroizing<[u8; 32]>> {
    let key = SecretKey::from_pkcs8_der(&unb64(private)?)?;
    let peer = PublicKey::from_public_key_der(&unb64(public)?)?;
    let raw = p256::ecdh::diffie_hellman(key.to_nonzero_scalar(), peer.as_affine());
    // .NET ECDiffieHellman.DeriveKeyFromHash(SHA256) hashes raw shared X first.
    Ok(Zeroizing::new(hash(raw.raw_secret_bytes())))
}
pub fn sign(private: &str, data: &[u8]) -> Result<String> {
    let key = SigningKey::from_pkcs8_der(&unb64(private)?)?;
    let signature: Signature = key.sign(data);
    Ok(b64(signature.to_bytes()))
}
pub fn verify(public: &str, data: &[u8], signature: &str) -> bool {
    (|| -> Result<()> {
        let key = VerifyingKey::from_public_key_der(&unb64(public)?)?;
        key.verify(data, &Signature::from_slice(&unb64(signature)?)?)?;
        Ok(())
    })()
    .is_ok()
}
pub fn encrypt(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], body: &mut Vec<u8>) -> Result<()> {
    Cipher::new(key).encrypt(nonce, aad, body)
}
pub fn decrypt(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], body: &mut Vec<u8>) -> Result<()> {
    Cipher::new(key).decrypt(nonce, aad, body)
}
pub struct Cipher(LessSafeKey);
impl Cipher {
    pub fn new(key: &[u8; 32]) -> Self {
        Self(LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM, key).expect("AES256 fixed key"),
        ))
    }
    pub fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], body: &mut Vec<u8>) -> Result<()> {
        self.0
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(*nonce), Aad::from(aad), body)
            .map_err(|_| anyhow::anyhow!("AEAD encryption failed"))
    }
    pub fn decrypt(&self, nonce: &[u8; 12], aad: &[u8], body: &mut Vec<u8>) -> Result<()> {
        let plain = self
            .0
            .open_in_place(Nonce::assume_unique_for_key(*nonce), Aad::from(aad), body)
            .map_err(|_| anyhow::anyhow!("AEAD authentication failed"))?;
        let size = plain.len();
        body.truncate(size);
        Ok(())
    }
    pub fn packet(&self, nonce: &[u8; 12], header: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
        let mut output = Vec::with_capacity(header.len() + payload.len() + 16);
        output.extend_from_slice(header);
        output.extend_from_slice(payload);
        let tag = self
            .0
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(*nonce),
                Aad::from(header),
                &mut output[header.len()..],
            )
            .map_err(|_| anyhow::anyhow!("AEAD encryption failed"))?;
        output.extend_from_slice(tag.as_ref());
        Ok(output)
    }
}
pub fn seal(key: &[u8; 32], aad: &[u8], plain: &[u8]) -> Result<String> {
    let nonce = random::<12>();
    let mut cipher = plain.to_vec();
    encrypt(key, &nonce, aad, &mut cipher)?;
    let tag = cipher.split_off(cipher.len() - 16);
    Ok(b64(
        [nonce.as_slice(), tag.as_slice(), cipher.as_slice()].concat()
    ))
}
pub fn open(key: &[u8; 32], aad: &[u8], cipher: &str, max: usize) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(cipher.len() <= max, "encrypted payload too large");
    let bytes = unb64(cipher)?;
    ensure!(bytes.len() >= 29, "encrypted payload truncated");
    let mut body = [&bytes[28..], &bytes[12..28]].concat();
    decrypt(key, bytes[..12].try_into()?, aad, &mut body)?;
    Ok(Zeroizing::new(body))
}

// Signing must preserve .NET's exact JSON member order and default escaping.
// This is a wire compatibility function, not an invented canonical JSON format.
pub fn signed_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    fn write(v: &serde_json::Value, out: &mut String) {
        use serde_json::Value::*;
        match v {
            Null => out.push_str("null"),
            Bool(v) => out.push_str(if *v { "true" } else { "false" }),
            Number(v) => out.push_str(&v.to_string()),
            String(v) => {
                out.push('"');
                for c in v.chars() {
                    match c {
                        '"' => out.push_str("\\u0022"),
                        '\\' => out.push_str("\\\\"),
                        '\n' => out.push_str("\\n"),
                        '\r' => out.push_str("\\r"),
                        '\t' => out.push_str("\\t"),
                        '\u{8}' => out.push_str("\\b"),
                        '\u{c}' => out.push_str("\\f"),
                        c if !c.is_ascii()
                            || c.is_control()
                            || matches!(c, '\'' | '<' | '>' | '&' | '+') =>
                        {
                            let mut units = [0; 2];
                            for unit in c.encode_utf16(&mut units) {
                                out.push_str(&format!("\\u{unit:04X}"));
                            }
                        }
                        c => out.push(c),
                    }
                }
                out.push('"');
            }
            Array(v) => {
                out.push('[');
                for (i, x) in v.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(x, out);
                }
                out.push(']');
            }
            Object(v) => {
                out.push('{');
                for (i, (k, x)) in v.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(&String(k.clone()), out);
                    out.push(':');
                    write(x, out);
                }
                out.push('}');
            }
        }
    }
    let mut out = String::new();
    write(&serde_json::to_value(value)?, &mut out);
    Ok(out.into_bytes())
}
pub fn check_name(name: &str) -> Result<()> {
    if name.is_empty() || name.encode_utf16().count() > 64 || name.chars().any(char::is_control) {
        bail!("device/network name must contain 1..64 non-control UTF-16 units")
    };
    Ok(())
}
