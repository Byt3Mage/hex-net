//! AEAD over a vetted implementation.
//!
//! The rules that matter are about using one correctly: a nonce is never
//! repeated, the header is authenticated as associated data, and a failed
//! open invalidates the whole packet.

use chacha20poly1305::aead::inout::InOutBuf;
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag};

pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

/// Largest encrypted blob handled: a ticket or cookie with nonce and tag.
pub const MAX_BLOB: usize = 512;

pub type Key = [u8; 32];

pub struct Blob<const N: usize> {
    pub data: [u8; N],
    pub len: usize,
}

impl<const N: usize> Blob<N> {
    pub fn as_slice(&self) -> &[u8] {
        debug_assert!(self.len <= N);
        &self.data[..self.len]
    }
}

/// Both directions' keys for one session.
///
/// Fixed for the session's life, including across resumes. The connection id
/// forms half of every nonce, so a new id gives a disjoint nonce space.
#[derive(Clone, Copy)]
pub struct Keys {
    pub client_to_server: Key,
    pub server_to_client: Key,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptoError;

/// One direction of one connection.
pub struct Cipher {
    inner: ChaCha20Poly1305,
    conn_id: u32,
}

impl Cipher {
    pub fn new(key: &Key, conn_id: u32) -> Self {
        Self { inner: ChaCha20Poly1305::new(key.into()), conn_id }
    }

    /// nonce = conn_id || sequence.
    ///
    /// Unique per packet because a connection id is not reused while its keys
    /// live and a sequence never repeats within a connection. Repeating a
    /// nonce would break confidentiality outright, which is why a packet is
    /// never retransmitted; its contents are resent under a new sequence.
    #[inline]
    fn nonce(&self, sequence: u64) -> Nonce {
        let mut out = [0u8; NONCE_LEN];
        out[0..4].copy_from_slice(&self.conn_id.to_le_bytes());
        out[4..12].copy_from_slice(&sequence.to_le_bytes());
        out.into()
    }

    /// Encrypts `buf[header_len..body_end]` in place and appends the tag.
    /// The header is authenticated as associated data, so it stays readable
    /// but cannot be altered. Returns the total packet length.
    pub fn encrypt(
        &self,
        sequence: u64,
        buf: &mut [u8],
        header_len: usize,
        body_end: usize,
    ) -> Result<usize, CryptoError> {
        if (body_end < header_len) || ((body_end + TAG_LEN) > buf.len()) {
            return Err(CryptoError);
        }
        let (header, rest) = buf.split_at_mut(header_len);
        let (body, rest) = rest.split_at_mut(body_end - header_len);

        let tag = self
            .inner
            .encrypt_inout_detached(&self.nonce(sequence), header, InOutBuf::from(body))
            .map_err(|_| CryptoError)?;

        rest[..TAG_LEN].copy_from_slice(&tag);
        Ok(body_end + TAG_LEN)
    }

    /// Verifies and decrypts in place. Returns the plaintext length.
    ///
    /// On failure the buffer may hold partially decrypted, attacker-controlled
    /// bytes; the caller must discard the entire packet.
    pub fn decrypt(
        &self,
        seq: u64,
        buf: &mut [u8],
        header_len: usize,
        packet_len: usize,
    ) -> Result<usize, CryptoError> {
        if (packet_len > buf.len()) || (packet_len < (header_len + TAG_LEN)) {
            return Err(CryptoError);
        }
        let body_len = packet_len - header_len - TAG_LEN;
        let (header, rest) = buf[..packet_len].split_at_mut(header_len);
        let (body, tag) = rest.split_at_mut(body_len);
        let tag = Tag::try_from(&tag[..]).map_err(|_| CryptoError)?;

        self.inner
            .decrypt_inout_detached(&self.nonce(seq), header, InOutBuf::from(body), &tag)
            .map_err(|_| CryptoError)?;

        Ok(body_len)
    }
}

/// Encrypts into `out`: nonce || ciphertext || tag. Returns the length written.
///
/// Tickets and cookies have no sequence to derive a nonce from, so they carry
/// a random one. Writing into a caller buffer keeps this path allocation-free,
/// which matters because it runs on unauthenticated packets.
pub fn encrypt_blob(key: &Key, blob: &[u8], aad: &[u8], out: &mut [u8]) -> Result<usize, CryptoError> {
    let end = NONCE_LEN + blob.len() + TAG_LEN;

    if out.len() < end {
        return Err(CryptoError);
    }

    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| CryptoError)?;

    out[..NONCE_LEN].copy_from_slice(&nonce);
    let body_end = NONCE_LEN + blob.len();
    out[NONCE_LEN..body_end].copy_from_slice(blob);

    let tag = ChaCha20Poly1305::new(&(*key).into())
        .encrypt_inout_detached(&nonce.into(), aad, InOutBuf::from(&mut out[NONCE_LEN..body_end]))
        .map_err(|_| CryptoError)?;

    out[body_end..end].copy_from_slice(tag.as_slice());
    Ok(end)
}

/// Verifies and decrypts into `out`. Returns the plaintext length. Rejects
/// rather than truncating when the plaintext exceeds `out`.
pub fn decrypt_blob(key: &Key, blob: &[u8], aad: &[u8], out: &mut [u8]) -> Result<usize, CryptoError> {
    if blob.len() < (NONCE_LEN + TAG_LEN) {
        return Err(CryptoError);
    }
    let (nonce, rest) = blob.split_at(NONCE_LEN);
    let (ciphertext, tag) = rest.split_at(rest.len() - TAG_LEN);
    if out.len() < ciphertext.len() {
        return Err(CryptoError);
    }

    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| CryptoError)?;
    let tag = Tag::try_from(tag).map_err(|_| CryptoError)?;

    let out = &mut out[..ciphertext.len()];
    out.copy_from_slice(ciphertext);

    ChaCha20Poly1305::new(&(*key).into())
        .decrypt_inout_detached(&nonce.into(), aad, InOutBuf::from(&mut out[..]), &tag)
        .map_err(|_| CryptoError)?;

    Ok(ciphertext.len())
}

pub fn generate_key() -> Key {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).expect("OS randomness unavailable");
    key
}
