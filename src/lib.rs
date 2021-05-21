#![forbid(unsafe_code)]

use blake2::digest::{Update, VariableOutput};
use blake2::VarBlake2b;
use core::fmt::{self, Display};
use crypto_box::aead::Aead;
use generic_array::GenericArray;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    /// Ciphertext verification failed.
    VerificationFailed,
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::VerificationFailed => write!(f, "Verification failed"),
        }
    }
}

/// Alias for a public key
pub type PublicKey = [u8; 32];

/// Alias for a secret key
pub type SecretKey = [u8; 32];

/// A key pair
pub struct KeyPair {
    pk: PublicKey,
    sk: PublicKey,
}

impl KeyPair {
    /// Create a new key pair
    pub fn create() -> Self {
        let mut rng = rand_core::OsRng;
        let sk = crypto_box::SecretKey::generate(&mut rng);
        let pk = sk.public_key();
        Self {
            pk: *pk.as_bytes(),
            sk: sk.to_bytes(),
        }
    }
}

/// Number of additional bytes in a ciphertext compared to the corresponding plaintext
pub const ABYTES: usize = 32 + 16;

type Nonce = [u8; 24];

fn create_nonce(pk1: PublicKey, pk2: PublicKey) -> Nonce {
    let mut hasher = VarBlake2b::new(24).unwrap();
    hasher.update(pk1);
    hasher.update(pk2);
    let mut nonce = [0u8; 24];
    hasher.finalize_variable(|h| nonce.copy_from_slice(h));
    nonce
}

/// Encrypt a message `msg` for a peer whoose public key is `peer_pk`
pub fn seal(msg: impl AsRef<[u8]>, peer_pk: PublicKey) -> Vec<u8> {
    let msg = msg.as_ref();
    let ekp = KeyPair::create();
    let nonce = create_nonce(ekp.pk, peer_pk);
    let mut ciphertext = vec![0u8; msg.len() + ABYTES];
    ciphertext[0..32].copy_from_slice(&ekp.pk);
    let box_ = crypto_box::Box::new(
        &crypto_box::PublicKey::from(peer_pk),
        &crypto_box::SecretKey::from(ekp.sk),
    );
    let boxed = box_
        .encrypt(&GenericArray::from_slice(&nonce), msg)
        .unwrap();
    ciphertext[32..].copy_from_slice(&boxed);
    ciphertext
}

/// Decrypt a ciphertext `ciphertext` using the key pair `kp`
pub fn open(ciphertext: impl AsRef<[u8]>, kp: &KeyPair) -> Result<Vec<u8>, Error> {
    let ciphertext = ciphertext.as_ref();
    if ciphertext.len() < ABYTES {
        return Err(Error::VerificationFailed);
    }
    let mut epk = [0u8; 32];
    epk.copy_from_slice(&ciphertext[0..32]);
    let nonce = create_nonce(epk, kp.pk);
    let box_ = crypto_box::Box::new(
        &crypto_box::PublicKey::from(epk),
        &crypto_box::SecretKey::from(kp.sk),
    );
    box_.decrypt(&GenericArray::from_slice(&nonce), &ciphertext[32..])
        .map_err(|_| Error::VerificationFailed)
}

#[cfg(test)]
mod test {
    use crate as sealed_box;

    #[test]
    fn test_sealed_box() {
        // Recipient: create a new key pair
        let recipient_kp = sealed_box::KeyPair::create();

        // Message to send
        let msg = b"test";

        //  Sender: encrypt the message for the recipient whose public key is recipient_kp.pk
        let ciphertext = sealed_box::seal(msg, recipient_kp.pk);

        // Recipient: decrypt the ciphertext using the key pair
        let decrypted_msg = sealed_box::open(&ciphertext, &recipient_kp).unwrap();

        assert_eq!(msg[..], decrypted_msg);
    }
}
