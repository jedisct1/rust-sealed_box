# sealed boxes for Rust

This is a pure Rust implementation of [libsodium sealed boxes](https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes).

Usage:

```rust
// Recipient: create a new key pair
let recipient_kp = sealed_box::KeyPair::create();

//  Sender: encrypt the message for the recipient whose public key is recipient_kp.pk
let msg = b"test";
let ciphertext = sealed_box::seal(msg, recipient_kp.pk);

// Recipient: decrypt the ciphertext using the key pair
let decrypted_msg = sealed_box::open(&ciphertext, &recipient_kp).unwrap();

assert_eq!(msg[..], decrypted_msg);
```