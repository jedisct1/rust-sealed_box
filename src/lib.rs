use core::fmt::{self, Display};

mod zig {
    use std::os::raw::c_int;

    extern "C" {
        pub fn seal(c: *mut u8, c_len: usize, m: *const u8, m_len: usize, pk: *const u8) -> i32;
        pub fn unseal(
            m: *mut u8,
            m_len: usize,
            c: *const u8,
            c_len: usize,
            pk: *const u8,
            sk: *const u8,
        ) -> i32;

        pub fn keygen(pk: *mut u8, sk: *mut u8);

        pub fn keygen_from_seed(pk: *mut u8, sk: *mut u8, seed: *const u8) -> c_int;
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    /// Ciphertext verification failed.
    VerificationFailed,

    /// Weak key detected.
    WeakKey,
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::VerificationFailed => write!(f, "Verification failed"),
            Error::WeakKey => write!(f, "Weak key detected"),
        }
    }
}

/// Alias for a public key
pub type PublicKey = [u8; 32];

/// Alias for a secret key
pub type SecretKey = [u8; 32];

/// Alias for a seed
pub type Seed = [u8; 32];

/// A key pair
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyPair {
    /// The public key component.
    pub pk: PublicKey,

    /// The secret key component.
    pub sk: SecretKey,
}

impl KeyPair {
    /// Create a new key pair
    pub fn create() -> Self {
        let mut pk = [0u8; 32];
        let mut sk = [0u8; 32];
        unsafe { zig::keygen(pk.as_mut_ptr(), sk.as_mut_ptr()) };
        Self { pk, sk }
    }

    /// Create a new key pair from a seed
    pub fn from_seed(seed: Seed) -> Result<Self, Error> {
        let mut pk = [0u8; 32];
        let mut sk = [0u8; 32];
        if unsafe { zig::keygen_from_seed(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr()) } != 0 {
            return Err(Error::WeakKey);
        }
        Ok(Self { pk, sk })
    }

    /// Serialize a key pair to bytes
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[0..31].copy_from_slice(&self.pk);
        buf[32..63].copy_from_slice(&self.sk);
        buf
    }

    /// Deserialize a key pair from bytes
    pub fn from_bytes(&self, buf: &[u8; 64]) -> Self {
        let mut pk = [0u8; 32];
        let mut sk = [0u8; 32];
        pk.copy_from_slice(&buf[0..31]);
        sk.copy_from_slice(&buf[32..63]);
        Self { pk, sk }
    }

    /// Create a key pair from components
    pub fn new(pk: PublicKey, sk: SecretKey) -> Self {
        Self { pk, sk }
    }
}

/// Number of additional bytes in a ciphertext compared to the corresponding
/// plaintext
pub const ABYTES: usize = 32 + 16;

/// Encrypt a message `msg` for a peer whoose public key is `peer_pk`
pub fn seal(msg: impl AsRef<[u8]>, peer_pk: PublicKey) -> Vec<u8> {
    let msg = msg.as_ref();
    let ciphertext_len = msg.len() + ABYTES;
    let mut ciphertext = Vec::with_capacity(ciphertext_len);
    unsafe {
        zig::seal(
            ciphertext.as_mut_ptr(),
            ciphertext_len,
            msg.as_ptr(),
            msg.len(),
            peer_pk.as_ptr(),
        );
        ciphertext.set_len(ciphertext_len);
    };
    ciphertext
}

/// Decrypt a ciphertext `ciphertext` using the key pair `kp`
pub fn open(ciphertext: impl AsRef<[u8]>, kp: &KeyPair) -> Result<Vec<u8>, Error> {
    let ciphertext = ciphertext.as_ref();
    if ciphertext.len() < ABYTES {
        return Err(Error::VerificationFailed);
    }
    let mut msg = vec![0u8; ciphertext.len() - ABYTES];
    if unsafe {
        zig::unseal(
            msg.as_mut_ptr(),
            msg.len(),
            ciphertext.as_ptr(),
            ciphertext.len(),
            kp.pk.as_ptr(),
            kp.sk.as_ptr(),
        )
    } != 0
    {
        return Err(Error::VerificationFailed);
    }
    Ok(msg)
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

        //  Sender: encrypt the message for the recipient whose public key is
        // recipient_kp.pk
        let ciphertext = sealed_box::seal(msg, recipient_kp.pk);

        // Recipient: decrypt the ciphertext using the key pair
        let decrypted_msg = sealed_box::open(ciphertext, &recipient_kp).unwrap();
        assert_eq!(msg[..], decrypted_msg);
    }

    #[test]
    fn test_sealed_box_existing_kp() {
        // Recipient: create a key pair from existing data
        let pk = [
            0x25, 0xb2, 0x9d, 0xb0, 0x35, 0x7a, 0x5d, 0x2c, 0xb7, 0x7d, 0xd2, 0xd5, 0x7a, 0xfb,
            0xbf, 0x30, 0xa2, 0x80, 0x23, 0xda, 0x5f, 0x2d, 0x7b, 0x80, 0xdf, 0x86, 0x65, 0xe4,
            0xbb, 0x0d, 0x45, 0x6f,
        ];
        let sk = [
            0xaa, 0x5b, 0xc4, 0xf5, 0x16, 0xe4, 0x26, 0xe2, 0x30, 0xc6, 0x9f, 0xcc, 0x19, 0x62,
            0x12, 0x67, 0x18, 0xf4, 0x4d, 0x63, 0x41, 0x1d, 0x6d, 0xb4, 0xa9, 0x68, 0xb2, 0xe7,
            0xa5, 0x64, 0x22, 0x3a,
        ];
        let recipient_kp = sealed_box::KeyPair::new(pk, sk);

        // Message to send
        let msg = b"test";

        //  Sender: encrypt the message for the recipient whose public key is
        // recipient_kp.pk
        let ciphertext = sealed_box::seal(msg, recipient_kp.pk);

        // Recipient: decrypt the ciphertext using the key pair
        let decrypted_msg = sealed_box::open(ciphertext, &recipient_kp).unwrap();

        assert_eq!(msg[..], decrypted_msg);
    }

    #[test]
    fn test_keygen_from_seed() {
        let seed = [0x01u8; 32];
        let seed_other = [0x02u8; 32];
        let kp = sealed_box::KeyPair::from_seed(seed).unwrap();
        let kp_eq = sealed_box::KeyPair::from_seed(seed).unwrap();
        let kp_other = sealed_box::KeyPair::from_seed(seed_other).unwrap();
        assert_eq!(kp.sk, kp_eq.sk);
        assert_eq!(kp.pk, kp_eq.pk);
        assert_ne!(kp.sk, kp_other.sk);
    }
}
