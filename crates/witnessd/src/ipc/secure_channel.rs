// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Encrypted channel wrapper for inter-component communication

use chacha20poly1305::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvError, SendError, Sender};
use zeroize::{Zeroize, Zeroizing};

/// Max nonce counter value before we refuse to encrypt. ChaCha20-Poly1305
/// requires unique nonces per key; wrapping to 0 would reuse a nonce and
/// break authenticated encryption. In practice an ephemeral in-process
/// channel will never reach this, but we guard it anyway.
const NONCE_COUNTER_MAX: u64 = u64::MAX - 1;

/// Max bincode payload size accepted on the secure channel.
/// Prevents a malicious or buggy sender from causing unbounded allocation.
/// Uses the same cap as IPC wire frames.
const MAX_SECURE_CHANNEL_PAYLOAD: usize = super::messages::MAX_MESSAGE_SIZE;

/// Factory for creating matched sender/receiver pairs with ChaCha20-Poly1305 encryption.
#[derive(Debug)]
pub struct SecureChannel<T> {
    _phantom: std::marker::PhantomData<T>,
}

/// Wire-format encrypted message with nonce and ciphertext.
#[derive(Debug)]
pub struct EncryptedMessage {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

impl<T: serde::Serialize + serde::de::DeserializeOwned> SecureChannel<T> {
    /// Create a matched sender/receiver pair sharing a fresh random key.
    pub fn new_pair() -> (SecureSender<T>, SecureReceiver<T>) {
        let (tx, rx) = mpsc::channel();

        // Hold key bytes in Zeroizing so they are wiped when this scope exits.
        let key_bytes: Zeroizing<[u8; 32]> = {
            let generated = ChaCha20Poly1305::generate_key(&mut OsRng);
            let mut bytes = Zeroizing::new([0u8; 32]);
            bytes.copy_from_slice(generated.as_slice());
            bytes
        };

        // Build sender and receiver ciphers independently; no clone of key material.
        let sender_cipher = ChaCha20Poly1305::new(Key::from_slice(&*key_bytes));
        let receiver_cipher = ChaCha20Poly1305::new(Key::from_slice(&*key_bytes));
        // key_bytes drops here and is zeroized by Zeroizing.

        // Generate a random 4-byte nonce prefix to fill nonce bytes [0..4],
        // preventing the first 4 bytes from always being zero.
        let mut nonce_prefix = Zeroizing::new([0u8; 4]);
        OsRng.fill_bytes(&mut *nonce_prefix);

        let sender = SecureSender {
            tx,
            cipher: sender_cipher,
            nonce_counter: AtomicU64::new(0),
            nonce_prefix,
            _phantom: std::marker::PhantomData,
        };

        let receiver = SecureReceiver {
            rx,
            cipher: receiver_cipher,
            _phantom: std::marker::PhantomData,
        };

        (sender, receiver)
    }
}

/// Sending half of an encrypted channel; encrypts and sends typed values.
pub struct SecureSender<T> {
    tx: Sender<EncryptedMessage>,
    cipher: ChaCha20Poly1305,
    pub(super) nonce_counter: AtomicU64,
    /// Random prefix for nonce bytes [0..4], generated once at channel creation.
    nonce_prefix: Zeroizing<[u8; 4]>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> std::fmt::Debug for SecureSender<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureSender")
            .field("cipher", &"[ChaCha20Poly1305]")
            .field("nonce_counter", &self.nonce_counter.load(Ordering::SeqCst))
            .finish()
    }
}

impl<T: serde::Serialize> SecureSender<T> {
    /// Serialize, encrypt, and send a value through the channel.
    pub fn send(&self, value: T) -> Result<(), SendError<EncryptedMessage>> {
        let plaintext = Zeroizing::new(
            bincode::serde::encode_to_vec(&value, bincode::config::standard()).map_err(|_| {
                SendError(EncryptedMessage {
                    nonce: [0; 12],
                    ciphertext: vec![],
                })
            })?,
        );

        // Reserve a nonce slot via compare_exchange; only commit after successful encrypt.
        let counter = loop {
            let current = self.nonce_counter.load(Ordering::SeqCst);
            if current >= NONCE_COUNTER_MAX {
                return Err(SendError(EncryptedMessage {
                    nonce: [0; 12],
                    ciphertext: vec![],
                }));
            }
            match self.nonce_counter.compare_exchange(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(val) => break val,
                Err(_) => continue,
            }
        };
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..4].copy_from_slice(&*self.nonce_prefix);
        nonce_bytes[4..].copy_from_slice(&counter.to_le_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|_| {
                SendError(EncryptedMessage {
                    nonce: [0; 12],
                    ciphertext: vec![],
                })
            })?;

        self.tx.send(EncryptedMessage {
            nonce: nonce_bytes,
            ciphertext,
        })
    }
}

/// Receiving half of an encrypted channel; decrypts and deserializes typed values.
pub struct SecureReceiver<T> {
    rx: Receiver<EncryptedMessage>,
    cipher: ChaCha20Poly1305,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> std::fmt::Debug for SecureReceiver<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureReceiver")
            .field("cipher", &"[ChaCha20Poly1305]")
            .finish()
    }
}

impl<T: serde::de::DeserializeOwned> SecureReceiver<T> {
    /// Block until a message arrives, then decrypt and deserialize it.
    pub fn recv(&self) -> Result<T, RecvError> {
        let msg = self.rx.recv()?;
        let nonce = Nonce::from_slice(&msg.nonce);

        let mut plaintext = self
            .cipher
            .decrypt(nonce, msg.ciphertext.as_ref())
            .map_err(|_| RecvError)?;

        if plaintext.len() > MAX_SECURE_CHANNEL_PAYLOAD {
            plaintext.zeroize();
            return Err(RecvError);
        }

        let (value, _): (T, usize) = bincode::serde::decode_from_slice(
            &plaintext,
            bincode::config::standard().with_limit::<{ super::messages::MAX_MESSAGE_SIZE }>(),
        )
        .map_err(|_| RecvError)?;

        plaintext.zeroize();

        Ok(value)
    }
}
