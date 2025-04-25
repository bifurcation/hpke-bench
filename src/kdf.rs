pub trait Kdf {
    const ID: [u8; 2];
    const N_H: usize;

    fn extract(salt: &[u8], ikm: &[u8]) -> Vec<u8>;
    fn expand(prk: &[u8], info: &[u8], L: usize) -> Vec<u8>;

    fn labeled_extract(suite_id: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Vec<u8> {
        use crate::concat;
        let labeled_ikm = concat(&[b"HPKE-v1", suite_id, label, ikm]);
        Self::extract(salt, &labeled_ikm)
    }

    fn labeled_expand(suite_id: &[u8], prk: &[u8], label: &[u8], info: &[u8], L: usize) -> Vec<u8> {
        use crate::{concat, i2osp};
        let labeled_info = concat(&[&i2osp(L, 2), b"HPKE-v1", suite_id, label, info]);
        Self::expand(prk, &labeled_info, L)
    }
}

use hkdf::Hkdf;
use sha2::{Sha256, Sha384, Sha512};

pub struct HkdfSha256;

impl Kdf for HkdfSha256 {
    const ID: [u8; 2] = [0x00, 0x01];
    const N_H: usize = 32;

    fn extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
        prk.to_vec()
    }

    fn expand(prk: &[u8], info: &[u8], L: usize) -> Vec<u8> {
        let mut okm = vec![0; L];
        let hk = Hkdf::<Sha256>::from_prk(prk).unwrap();
        hk.expand(info, &mut okm).unwrap();
        okm
    }
}

pub struct HkdfSha384;

impl Kdf for HkdfSha384 {
    const ID: [u8; 2] = [0x00, 0x02];
    const N_H: usize = 48;

    fn extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        let (prk, _) = Hkdf::<Sha384>::extract(Some(salt), ikm);
        prk.to_vec()
    }

    fn expand(prk: &[u8], info: &[u8], L: usize) -> Vec<u8> {
        let mut okm = vec![0; L];
        let hk = Hkdf::<Sha384>::from_prk(prk).unwrap();
        hk.expand(info, &mut okm).unwrap();
        okm
    }
}

pub struct HkdfSha512;

impl Kdf for HkdfSha512 {
    const ID: [u8; 2] = [0x00, 0x03];
    const N_H: usize = 64;

    fn extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        let (prk, _) = Hkdf::<Sha512>::extract(Some(salt), ikm);
        prk.to_vec()
    }

    fn expand(prk: &[u8], info: &[u8], L: usize) -> Vec<u8> {
        let mut okm = vec![0; L];
        let hk = Hkdf::<Sha512>::from_prk(prk).unwrap();
        hk.expand(info, &mut okm).unwrap();
        okm
    }
}
