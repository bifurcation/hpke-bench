#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(unused_variables)]

mod aead;
mod kdf;
mod kem;

pub use aead::*;
pub use kdf::*;
pub use kem::*;

use rand_core::CryptoRngCore;

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    let len = parts.iter().map(|x| x.len()).sum();
    let mut out = Vec::with_capacity(len);

    for part in parts.iter() {
        out.extend_from_slice(part);
    }

    out
}

fn i2osp(n: usize, w: usize) -> Vec<u8> {
    let b = n.to_be_bytes();
    let mut v = vec![0; w];

    if b.len() < v.len() {
        let start = v.len() - b.len();
        v[start..].copy_from_slice(&b);
    } else {
        let start = b.len() - v.len();
        v.copy_from_slice(&b[start..]);
    }

    v
}

pub trait Role {}

pub struct Sender;
impl Role for Sender {}

pub struct Receiver;
impl Role for Receiver {}

#[derive(Copy, Clone)]
enum Mode {
    Base,
    Psk,
}

impl From<Mode> for u8 {
    fn from(mode: Mode) -> u8 {
        match mode {
            Mode::Base => 0x00,
            Mode::Psk => 0x01,
        }
    }
}

pub struct Context<A, R>
where
    A: Aead,
    R: Role,
{
    key: Vec<u8>,
    base_nonce: Vec<u8>,
    exporter_secret: Vec<u8>,
    seq: usize,
    _aead: core::marker::PhantomData<A>,
    _role: core::marker::PhantomData<R>,
}

impl<A, R> Context<A, R>
where
    A: Aead,
    R: Role,
{
    fn new(key: Vec<u8>, base_nonce: Vec<u8>, exporter_secret: Vec<u8>) -> Self {
        Self {
            key,
            base_nonce,
            exporter_secret,
            seq: 0,
            _aead: core::marker::PhantomData,
            _role: core::marker::PhantomData,
        }
    }

    // TODO(RLB) Export could go here, but would we would need to make this type generic on the KDF
    // so that we have access to labeled_expand.  And maybe also the KEM so that we can compute a
    // suite_id.

    fn increment_seq(&mut self) {
        // This will never happen in practice, because integers are small
        /*
        if self.seq >= (1 << (8 * A::N_N)) - 1 {
            panic!("Message limit reached");
        }
        */

        // Instead, just check for integer overflow
        self.seq = self.seq.checked_add(1).unwrap();
    }

    fn compute_nonce(&self) -> Vec<u8> {
        let mut seq_bytes = i2osp(self.seq, A::N_N);
        for i in 0..A::N_N {
            seq_bytes[i] ^= self.base_nonce[i];
        }
        seq_bytes
    }
}

impl<A> Context<A, Sender>
where
    A: Aead,
{
    fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Vec<u8> {
        let nonce = self.compute_nonce();
        let ct = A::seal(&self.key, &nonce, aad, pt);
        self.increment_seq();
        ct
    }
}

impl<A> Context<A, Receiver>
where
    A: Aead,
{
    fn open(&mut self, aad: &[u8], ct: &[u8]) -> Vec<u8> {
        let nonce = self.compute_nonce();
        let pt = A::open(&self.key, &nonce, aad, ct);
        self.increment_seq();
        pt
    }
}

pub struct Hpke<K, H, A>
where
    K: Kem,
    H: Kdf,
    A: Aead,
{
    _kem: core::marker::PhantomData<K>,
    _kdf: core::marker::PhantomData<H>,
    _aead: core::marker::PhantomData<A>,
}

impl<K, H, A> Hpke<K, H, A>
where
    K: Kem,
    H: Kdf,
    A: Aead,
{
    fn suite_id() -> [u8; 10] {
        let mut suite_id = [0; 10];

        suite_id[0..4].copy_from_slice(b"HPKE");
        suite_id[4..6].copy_from_slice(&K::ID);
        suite_id[6..8].copy_from_slice(&H::ID);
        suite_id[8..10].copy_from_slice(&A::ID);

        suite_id
    }

    fn verify_psk_inputs(mode: Mode, psk: Option<&[u8]>, psk_id: Option<&[u8]>) {
        if psk.is_some() != psk_id.is_some() {
            panic!("Inconsistent PSK inputs");
        }

        if psk.is_some() && matches!(mode, Mode::Base) {
            panic!("PSK input provided when not needed");
        }

        if !psk.is_some() && matches!(mode, Mode::Psk) {
            panic!("Missing required PSK input");
        }
    }

    fn key_schedule<R: Role>(
        mode: Mode,
        shared_secret: &[u8],
        info: &[u8],
        psk: Option<&[u8]>,
        psk_id: Option<&[u8]>,
    ) -> Context<A, R> {
        Self::verify_psk_inputs(mode, psk, psk_id);

        let suite_id = Self::suite_id();
        let psk = psk.unwrap_or_default();
        let psk_id = psk_id.unwrap_or_default();

        let psk_id_hash = H::labeled_extract(&suite_id, &[], b"psk_id_hash", psk_id);
        let info_hash = H::labeled_extract(&suite_id, &[], b"info_hash", info);
        let key_schedule_context = concat(&[&[u8::from(mode)], &psk_id_hash, &info_hash]);

        let secret = H::labeled_extract(&suite_id, shared_secret, b"secret", psk);

        let key = H::labeled_expand(&suite_id, &secret, b"key", &key_schedule_context, A::N_K);
        let base_nonce = H::labeled_expand(
            &suite_id,
            &secret,
            b"base_nonce",
            &key_schedule_context,
            A::N_N,
        );
        let exporter_secret =
            H::labeled_expand(&suite_id, &secret, b"exp", &key_schedule_context, H::N_H);

        Context::new(key, base_nonce, exporter_secret)
    }

    pub fn setup_base_s(
        rng: &mut impl CryptoRngCore,
        pkR: &K::EncapsulationKey,
        info: &[u8],
    ) -> (K::Ciphertext, Context<A, Sender>) {
        let (shared_secret, enc) = K::encap(rng, pkR);
        (
            enc,
            Self::key_schedule(Mode::Base, &shared_secret, info, None, None),
        )
    }

    pub fn setup_base_r(
        enc: &K::Ciphertext,
        skR: &K::DecapsulationKey,
        info: &[u8],
    ) -> Context<A, Receiver> {
        let shared_secret = K::decap(enc, skR);
        Self::key_schedule(Mode::Base, &shared_secret, info, None, None)
    }

    pub fn setup_psk_s(
        rng: &mut impl CryptoRngCore,
        pkR: &K::EncapsulationKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> (K::Ciphertext, Context<A, Sender>) {
        let (shared_secret, enc) = K::encap(rng, pkR);
        (
            enc,
            Self::key_schedule(Mode::Psk, &shared_secret, info, Some(psk), Some(psk_id)),
        )
    }

    pub fn setup_psk_r(
        enc: &K::Ciphertext,
        skR: &K::DecapsulationKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Context<A, Receiver> {
        let shared_secret = K::decap(enc, skR);
        Self::key_schedule(Mode::Psk, &shared_secret, info, Some(psk), Some(psk_id))
    }

    pub fn seal_base(
        rng: &mut impl CryptoRngCore,
        pkR: &K::EncapsulationKey,
        info: &[u8],
        aad: &[u8],
        pt: &[u8],
    ) -> (K::Ciphertext, Vec<u8>) {
        let (enc, mut ctx) = Self::setup_base_s(rng, pkR, info);
        let ct = ctx.seal(aad, pt);
        (enc, ct)
    }

    pub fn open_base(
        enc: &K::Ciphertext,
        skR: &K::DecapsulationKey,
        info: &[u8],
        aad: &[u8],
        ct: &[u8],
    ) -> Vec<u8> {
        let mut ctx = Self::setup_base_r(enc, skR, info);
        ctx.open(aad, ct)
    }

    pub fn seal_psk(
        rng: &mut impl CryptoRngCore,
        pkR: &K::EncapsulationKey,
        info: &[u8],
        aad: &[u8],
        pt: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> (K::Ciphertext, Vec<u8>) {
        let (enc, mut ctx) = Self::setup_psk_s(rng, pkR, info, psk, psk_id);
        let ct = ctx.seal(aad, pt);
        (enc, ct)
    }

    pub fn open_psk(
        enc: &K::Ciphertext,
        skR: &K::DecapsulationKey,
        info: &[u8],
        aad: &[u8],
        ct: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Vec<u8> {
        let mut ctx = Self::setup_psk_r(enc, skR, info, psk, psk_id);
        ctx.open(aad, ct)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn base<K, H, A>()
    where
        K: Kem,
        H: Kdf,
        A: Aead,
    {
        let mut rng = rand::thread_rng();

        let info = b"And turning toward the window, should say";
        let aad = b"That is not it at all";
        let pt = b"That is not what I meant, at all";

        let (dk, ek) = K::generate_key_pair(&mut rng);
        let (enc, ct) = Hpke::<K, H, A>::seal_base(&mut rng, &ek, info, aad, pt);
        assert_eq!(ct.len(), pt.len() + A::N_T);

        let pt_out = Hpke::<K, H, A>::open_base(&enc, &dk, info, aad, &ct);
        assert_eq!(pt, pt_out.as_slice());
    }

    #[test]
    fn base_all() {
        base::<DhkemP256HkdfSha256, HkdfSha256, Aes128Gcm>();
        base::<DhkemP384HkdfSha384, HkdfSha384, Aes256Gcm>();
        base::<DhkemP521HkdfSha512, HkdfSha512, Aes256Gcm>();
        base::<DhkemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>();
        base::<DhkemX448HkdfSha512, HkdfSha512, ChaCha20Poly1305>();
    }

    fn psk<K, H, A>()
    where
        K: Kem,
        H: Kdf,
        A: Aead,
    {
        let mut rng = rand::thread_rng();

        let info = b"And turning toward the window, should say";
        let aad = b"That is not it at all";
        let pt = b"That is not what I meant, at all";

        let psk = b"I should have been a pair of ragged claws";
        let psk_id = b"Scuttling across the floors of silent seas";

        let (dk, ek) = K::generate_key_pair(&mut rng);
        let (enc, ct) = Hpke::<K, H, A>::seal_psk(&mut rng, &ek, info, aad, pt, psk, psk_id);
        assert_eq!(ct.len(), pt.len() + A::N_T);

        let pt_out = Hpke::<K, H, A>::open_psk(&enc, &dk, info, aad, &ct, psk, psk_id);
        assert_eq!(pt, pt_out.as_slice());
    }

    #[test]
    fn psk_all() {
        psk::<DhkemP256HkdfSha256, HkdfSha256, Aes128Gcm>();
        psk::<DhkemP384HkdfSha384, HkdfSha384, Aes256Gcm>();
        psk::<DhkemP521HkdfSha512, HkdfSha512, Aes256Gcm>();
        psk::<DhkemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>();
        psk::<DhkemX448HkdfSha512, HkdfSha512, ChaCha20Poly1305>();
    }
}
