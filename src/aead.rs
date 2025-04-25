pub trait Aead {
    const ID: [u8; 2];
    const N_K: usize;
    const N_N: usize;
    const N_T: usize;

    fn seal(key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Vec<u8>;
    fn open(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Vec<u8>;
}

use aead::{Aead as _, KeyInit};

struct Aes128Gcm;

impl Aead for Aes128Gcm {
    const ID: [u8; 2] = [0x00, 0x01];
    const N_K: usize = 16;
    const N_N: usize = 12;
    const N_T: usize = 16;

    fn seal(key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Vec<u8> {
        let payload = aead::Payload { aad, msg: pt };
        let cipher = aes_gcm::Aes128Gcm::new(key.into());
        cipher.encrypt(nonce.into(), payload).unwrap()
    }

    fn open(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Vec<u8> {
        let payload = aead::Payload { aad, msg: ct };
        let cipher = aes_gcm::Aes128Gcm::new(key.into());
        cipher.decrypt(nonce.into(), payload).unwrap()
    }
}

struct Aes256Gcm;

impl Aead for Aes256Gcm {
    const ID: [u8; 2] = [0x00, 0x02];
    const N_K: usize = 32;
    const N_N: usize = 12;
    const N_T: usize = 16;

    fn seal(key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Vec<u8> {
        let payload = aead::Payload { aad, msg: pt };
        let cipher = aes_gcm::Aes256Gcm::new(key.into());
        cipher.encrypt(nonce.into(), payload).unwrap()
    }

    fn open(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Vec<u8> {
        let payload = aead::Payload { aad, msg: ct };
        let cipher = aes_gcm::Aes128Gcm::new(key.into());
        cipher.decrypt(nonce.into(), payload).unwrap()
    }
}

struct ChaCha29Poly1305;

impl Aead for ChaCha29Poly1305 {
    const ID: [u8; 2] = [0x00, 0x03];
    const N_K: usize = 32;
    const N_N: usize = 12;
    const N_T: usize = 16;

    fn seal(key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Vec<u8> {
        let payload = aead::Payload { aad, msg: pt };
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(key.into());
        cipher.encrypt(nonce.into(), payload).unwrap()
    }

    fn open(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Vec<u8> {
        let payload = aead::Payload { aad, msg: ct };
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(key.into());
        cipher.decrypt(nonce.into(), payload).unwrap()
    }
}
