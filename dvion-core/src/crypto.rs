use anyhow::{anyhow, bail, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use ml_kem::{
    Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey,
    Kem, Key as KemKey, KeyExport, KeyInit as KemKeyInit, MlKem768,
};
use sha2::Sha256;
use rand::rngs::OsRng;
use std::sync::atomic::{AtomicU64, Ordering};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public};

type Ek768 = EncapsulationKey<MlKem768>;
type Dk768 = DecapsulationKey<MlKem768>;

// ── ML-KEM-768 wrapper ────────────────────────────────────────────────────────

pub struct PqKem;

impl PqKem {
    pub fn new() -> Self {
        Self
    }

    /// Returns `(ek_bytes, dk_seed_bytes)`.
    pub fn keypair(&self) -> (Vec<u8>, Vec<u8>) {
        let (dk, ek) = MlKem768::generate_keypair();
        (ek.to_bytes().to_vec(), dk.to_bytes().to_vec())
    }

    /// Returns `(ct_bytes, ss_bytes)`.
    pub fn encapsulate(&self, ek_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let ek = parse_ek(ek_bytes)?;
        let (ct, ss) = ek.encapsulate();
        Ok((ct.to_vec(), ss.to_vec()))
    }

    /// Returns `ss_bytes`.
    pub fn decapsulate(&self, dk_bytes: &[u8], ct_bytes: &[u8]) -> Result<Vec<u8>> {
        let dk = parse_dk(dk_bytes)?;
        let ss = dk
            .decapsulate_slice(ct_bytes)
            .map_err(|_| anyhow!("ML-KEM ciphertext has wrong length: {} bytes", ct_bytes.len()))?;
        Ok(ss.to_vec())
    }
}

fn parse_ek(bytes: &[u8]) -> Result<Ek768> {
    let key = KemKey::<Ek768>::try_from(bytes)
        .map_err(|_| anyhow!("invalid EK length: {} bytes", bytes.len()))?;
    Ek768::new(&key).map_err(|e| anyhow!("invalid EK: {e}"))
}

fn parse_dk(bytes: &[u8]) -> Result<Dk768> {
    let key = KemKey::<Dk768>::try_from(bytes)
        .map_err(|_| anyhow!("invalid DK seed length: {} bytes", bytes.len()))?;
    Ok(Dk768::new(&key))
}

// ── Hybrid key derivation ─────────────────────────────────────────────────────

/// HKDF-SHA256 over X25519 || ML-KEM shared secrets.
/// Security holds as long as EITHER primitive remains unbroken.
pub fn hybrid_shared_secret(x25519_ss: &[u8; 32], mlkem_ss: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(32 + mlkem_ss.len());
    ikm.extend_from_slice(x25519_ss);
    ikm.extend_from_slice(mlkem_ss);

    let hkdf = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    hkdf.expand(b"dvion-vpn-v1-session-key", &mut okm)
        .expect("HKDF expand failed");
    okm
}

// ── Session cipher ────────────────────────────────────────────────────────────

/// ChaCha20-Poly1305 with a monotonic counter nonce.
/// The 8-byte counter is prepended to every ciphertext so the receiver can
/// reconstruct the nonce without keeping per-stream state.
pub struct SessionCipher {
    cipher: ChaCha20Poly1305,
    send_counter: AtomicU64,
}

impl SessionCipher {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
            send_counter: AtomicU64::new(0),
        }
    }

    /// Encrypt → `counter(8) ‖ ciphertext`
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let counter = self.send_counter.fetch_add(1, Ordering::Relaxed);
        let nonce = nonce_from_counter(counter);
        let ct = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow!("encrypt: {e}"))?;
        let mut out = Vec::with_capacity(8 + ct.len());
        out.extend_from_slice(&counter.to_be_bytes());
        out.extend(ct);
        Ok(out)
    }

    /// Decrypt `counter(8) ‖ ciphertext`
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 8 {
            bail!("packet too short ({} bytes)", data.len());
        }
        let counter = u64::from_be_bytes(data[..8].try_into().unwrap());
        let nonce = nonce_from_counter(counter);
        self.cipher
            .decrypt(&nonce, &data[8..])
            .map_err(|e| anyhow!("decrypt: {e}"))
    }
}

fn nonce_from_counter(counter: u64) -> Nonce {
    // 12-byte nonce: 4 zero bytes ‖ 8-byte big-endian counter
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    *Nonce::from_slice(&n)
}

// ── Handshake messages ────────────────────────────────────────────────────────
// Wire format (both directions):
//   [1]  msg_type
//   [32] X25519 public key
//   [2]  payload_len (big-endian)
//   [N]  payload (ML-KEM public key or ciphertext)

/// Sent by client: ephemeral X25519 pk + ML-KEM pk
pub struct ClientHello {
    pub x25519_pk: [u8; 32],
    pub mlkem_pk: Vec<u8>,
}

/// Sent by server: ephemeral X25519 pk + ML-KEM ciphertext
pub struct ServerHello {
    pub x25519_pk: [u8; 32],
    pub mlkem_ct: Vec<u8>,
}

pub struct ClientSecrets {
    pub x25519_secret: EphemeralSecret,
    pub mlkem_sk: Vec<u8>,
}

impl ClientHello {
    /// Generate a fresh ClientHello plus the secrets the client must keep.
    pub fn generate() -> (Self, ClientSecrets) {
        let x25519_secret = EphemeralSecret::random_from_rng(OsRng);
        let x25519_pk = *X25519Public::from(&x25519_secret).as_bytes();

        let kem = PqKem::new();
        let (mlkem_pk_bytes, mlkem_sk_bytes) = kem.keypair();

        (
            ClientHello {
                x25519_pk,
                mlkem_pk: mlkem_pk_bytes,
            },
            ClientSecrets {
                x25519_secret,
                mlkem_sk: mlkem_sk_bytes,
            },
        )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        encode_msg(0x01, &self.x25519_pk, &self.mlkem_pk)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let (x25519_pk, payload) = decode_msg(0x01, data)?;
        Ok(Self {
            x25519_pk,
            mlkem_pk: payload,
        })
    }
}

impl ServerHello {
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_msg(0x02, &self.x25519_pk, &self.mlkem_ct)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let (x25519_pk, payload) = decode_msg(0x02, data)?;
        Ok(Self {
            x25519_pk,
            mlkem_ct: payload,
        })
    }
}

fn encode_msg(msg_type: u8, x25519_pk: &[u8; 32], payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= 65535, "payload too large for u16 length field: {} bytes", payload.len());
    let mut out = Vec::with_capacity(1 + 32 + 2 + payload.len());
    out.push(msg_type);
    out.extend_from_slice(x25519_pk);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn decode_msg(expected_type: u8, data: &[u8]) -> Result<([u8; 32], Vec<u8>)> {
    if data.len() < 35 {
        bail!("message too short");
    }
    if data[0] != expected_type {
        bail!("wrong msg type: got 0x{:02x}", data[0]);
    }
    let x25519_pk: [u8; 32] = data[1..33].try_into()?;
    let payload_len = u16::from_be_bytes(data[33..35].try_into()?) as usize;
    if data.len() < 35 + payload_len {
        bail!("truncated message");
    }
    Ok((x25519_pk, data[35..35 + payload_len].to_vec()))
}

// ── Shared: complete the handshake from each side ─────────────────────────────

/// Server-side: receive ClientHello, derive session key, return ServerHello bytes + key.
pub fn server_derive_key(hello: &ClientHello) -> Result<(ServerHello, [u8; 32])> {
    // X25519 ephemeral
    let x25519_secret = EphemeralSecret::random_from_rng(OsRng);
    let x25519_server_pk = X25519Public::from(&x25519_secret);
    let client_x25519 = X25519Public::from(hello.x25519_pk);
    let x25519_ss = x25519_secret.diffie_hellman(&client_x25519);

    // ML-KEM: encapsulate to client's public key
    let kem = PqKem::new();
    let (ct_bytes, mlkem_ss_bytes) = kem.encapsulate(&hello.mlkem_pk)?;

    let session_key = hybrid_shared_secret(x25519_ss.as_bytes(), &mlkem_ss_bytes);

    Ok((
        ServerHello {
            x25519_pk: *x25519_server_pk.as_bytes(),
            mlkem_ct: ct_bytes,
        },
        session_key,
    ))
}

/// Client-side: receive ServerHello, derive session key.
pub fn client_derive_key(
    secrets: ClientSecrets,
    hello: &ServerHello,
) -> Result<[u8; 32]> {
    // X25519
    let server_x25519 = X25519Public::from(hello.x25519_pk);
    let x25519_ss = secrets.x25519_secret.diffie_hellman(&server_x25519);

    // ML-KEM: decapsulate
    let kem = PqKem::new();
    let mlkem_ss_bytes = kem.decapsulate(&secrets.mlkem_sk, &hello.mlkem_ct)?;

    Ok(hybrid_shared_secret(x25519_ss.as_bytes(), &mlkem_ss_bytes))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Both sides must arrive at the same session key.
    #[test]
    fn handshake_key_agreement() {
        let (client_hello, client_secrets) = ClientHello::generate();

        let (server_hello, server_key) =
            server_derive_key(&client_hello).expect("server_derive_key failed");

        let client_key =
            client_derive_key(client_secrets, &server_hello).expect("client_derive_key failed");

        assert_eq!(server_key, client_key, "session keys differ — handshake broken");
    }

    /// Encrypt then decrypt must round-trip.
    #[test]
    fn cipher_round_trip() {
        let key = [0x42u8; 32];
        let cipher = SessionCipher::new(&key);
        let plaintext = b"hello dvion vpn";

        let encrypted = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    /// Two different packets must produce different ciphertexts (counter advances).
    #[test]
    fn cipher_nonce_is_unique() {
        let cipher = SessionCipher::new(&[0u8; 32]);
        let ct1 = cipher.encrypt(b"packet one").unwrap();
        let ct2 = cipher.encrypt(b"packet one").unwrap();
        assert_ne!(ct1, ct2, "same nonce used twice — counter not advancing");
    }

    /// Tampered ciphertext must fail authentication.
    #[test]
    fn cipher_rejects_tamper() {
        let cipher = SessionCipher::new(&[0u8; 32]);
        let mut ct = cipher.encrypt(b"important packet").unwrap();
        ct[10] ^= 0xff; // flip a byte
        assert!(cipher.decrypt(&ct).is_err(), "tamper not detected");
    }
}
