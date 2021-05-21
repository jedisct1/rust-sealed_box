use core::fmt::{self, Display};

mod zig {
    extern "C" {
        pub fn seal(c: *mut u8, c_len: usize, m: *const u8, m_len: usize, pk: *const u8) -> i32;
        pub fn open(
            m: *mut u8,
            m_len: usize,
            c: *const u8,
            c_len: usize,
            pk: *const u8,
            sk: *const u8,
        ) -> i32;

        pub fn keygen(pk: *mut u8, sk: *mut u8);
    }
}

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
        let mut pk = [0u8; 32];
        let mut sk = [0u8; 32];
        unsafe { zig::keygen(pk.as_mut_ptr(), sk.as_mut_ptr()) };
        Self { pk, sk }
    }
}

/// Number of additional bytes in a ciphertext compared to the corresponding plaintext
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
        zig::open(
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

        //  Sender: encrypt the message for the recipient whose public key is recipient_kp.pk
        let ciphertext = sealed_box::seal(msg, recipient_kp.pk);

        // Recipient: decrypt the ciphertext using the key pair
        let decrypted_msg = sealed_box::open(&ciphertext, &recipient_kp).unwrap();

        assert_eq!(msg[..], decrypted_msg);
    }
}
