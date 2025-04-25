#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(unused_variables)]

mod aead;
mod kdf;
mod kem;

use aead::*;
use kdf::*;
use kem::*;

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
    let mut val = vec![0; w];
    for i in 0..w {
        val[i] = (n >> (8 * (w - i - 1))) as u8;
    }
    val
}

trait Role {}

struct Sender;
impl Role for Sender {}

struct Receiver;
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

struct Context<A, R>
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
        if self.seq >= (1 << (8 * A::N_N)) - 1 {
            // This will never happen in practice, because integers are small
            panic!("Message limit reached");
        }

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
        let pt = A::seal(&self.key, &nonce, aad, ct);
        self.increment_seq();
        pt
    }
}

struct Hpke<K, H, A>
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

    fn setup_base_s(
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

    fn setup_base_r(
        enc: &K::Ciphertext,
        skR: &K::DecapsulationKey,
        info: &[u8],
    ) -> Context<A, Receiver> {
        let shared_secret = K::decap(enc, skR);
        Self::key_schedule(Mode::Base, &shared_secret, info, None, None)
    }

    fn setup_psk_s(
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

    fn setup_psk_r(
        enc: &K::Ciphertext,
        skR: &K::DecapsulationKey,
        info: &[u8],
        psk: &[u8],
        psk_id: &[u8],
    ) -> Context<A, Receiver> {
        let shared_secret = K::decap(enc, skR);
        Self::key_schedule(Mode::Psk, &shared_secret, info, Some(psk), Some(psk_id))
    }
}
