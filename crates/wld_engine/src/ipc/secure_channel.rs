// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Encrypted channel wrapper for inter-component communication

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvError, SendError, Sender};
use zeroize::Zeroize;

/// Max nonce counter value before we refuse to encrypt. ChaCha20-Poly1305
/// requires unique nonces per key; wrapping to 0 would reuse a nonce and
/// break authenticated encryption. In practice an ephemeral in-process
/// channel will never reach this, but we guard it anyway.
const NONCE_COUNTER_MAX: u64 = u64::MAX - 1;

/// Max bincode payload size accepted on the secure channel.
/// Prevents a malicious or buggy sender from causing unbounded allocation.
/// Uses the same cap as IPC wire frames.
const MAX_SECURE_CHANNEL_PAYLOAD: usize = super::messages::MAX_MESSAGE_SIZE;

/// Typed channel pair with ChaCha20-Poly1305 encryption over `mpsc`
pub struct SecureChannel<T> {
    _phantom: std::marker::PhantomData<T>,
}

pub struct EncryptedMessage {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

impl<T: serde::Serialize + serde::de::DeserializeOwned> SecureChannel<T> {
    pub fn new_pair() -> (SecureSender<T>, SecureReceiver<T>) {
        let (tx, rx) = mpsc::channel();

        let mut key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let cipher = ChaCha20Poly1305::new(&key);
        key.as_mut_slice().zeroize();

        let sender = SecureSender {
            tx,
            cipher: cipher.clone(),
            nonce_counter: AtomicU64::new(0),
            _phantom: std::marker::PhantomData,
        };

        let receiver = SecureReceiver {
            rx,
            cipher,
            _phantom: std::marker::PhantomData,
        };

        (sender, receiver)
    }
}

pub struct SecureSender<T> {
    tx: Sender<EncryptedMessage>,
    cipher: ChaCha20Poly1305,
    pub(super) nonce_counter: AtomicU64,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: serde::Serialize> SecureSender<T> {
    pub fn send(&self, value: T) -> Result<(), SendError<EncryptedMessage>> {
        let plaintext = bincode::serde::encode_to_vec(&value, bincode::config::standard())
            .map_err(|_| {
                SendError(EncryptedMessage {
                    nonce: [0; 12],
                    ciphertext: vec![],
                })
            })?;

        let counter = self.nonce_counter.fetch_add(1, Ordering::SeqCst);
        if counter >= NONCE_COUNTER_MAX {
            return Err(SendError(EncryptedMessage {
                nonce: [0; 12],
                ciphertext: vec![],
            }));
        }
        let mut nonce_bytes = [0u8; 12];
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

pub struct SecureReceiver<T> {
    rx: Receiver<EncryptedMessage>,
    cipher: ChaCha20Poly1305,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: serde::de::DeserializeOwned> SecureReceiver<T> {
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
