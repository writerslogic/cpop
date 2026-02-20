//! Encrypted channel wrapper for inter-component communication

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvError, SendError, Sender};
use zeroize::Zeroize;

/// Secure channel that encrypts messages in transit
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

        // Generate ephemeral session key (never persisted)
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let cipher = ChaCha20Poly1305::new(&key);

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
    nonce_counter: AtomicU64,
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

        // Incrementing nonce (safe for ephemeral keys)
        let counter = self.nonce_counter.fetch_add(1, Ordering::SeqCst);
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

        let (value, _): (T, usize) =
            bincode::serde::decode_from_slice(&plaintext, bincode::config::standard())
                .map_err(|_| RecvError)?;

        plaintext.zeroize();

        Ok(value)
    }
}
