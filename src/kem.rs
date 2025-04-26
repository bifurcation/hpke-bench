use crate::kdf::{HkdfSha256, HkdfSha384, HkdfSha512, Kdf};

use rand_core::CryptoRngCore;

pub trait Kem {
    const ID: [u8; 2];
    const N_SECRET: usize;
    const N_ENC: usize;
    const N_PK: usize;
    const N_SK: usize;

    type EncapsulationKey;
    type DecapsulationKey;
    type Ciphertext;

    fn generate_key_pair(
        rng: &mut impl CryptoRngCore,
    ) -> (Self::DecapsulationKey, Self::EncapsulationKey);
    fn derive_key_pair(ikm: &[u8]) -> (Self::DecapsulationKey, Self::EncapsulationKey);
    fn serialize_public_key(pkX: &Self::EncapsulationKey) -> Vec<u8>;
    fn deserialize_public_key(pkXm: &[u8]) -> Self::EncapsulationKey;

    fn encap(
        rng: &mut impl CryptoRngCore,
        pkR: &Self::EncapsulationKey,
    ) -> (Vec<u8>, Self::Ciphertext);
    fn decap(enc: &Self::Ciphertext, skR: &Self::DecapsulationKey) -> Vec<u8>;
}

pub trait Curve {
    const N_ID: u16;
    const SUITE_ID: &[u8];
    const SCALAR_SIZE: usize;
    const POINT_SIZE: usize;
    const SECRET_SIZE: usize;

    type Scalar;
    type Point;

    fn generate_key_pair(rng: &mut impl CryptoRngCore) -> (Self::Scalar, Self::Point);
    fn derive_key_pair(ikm: &[u8]) -> (Self::Scalar, Self::Point);
    fn serialize_public_key(pkX: &Self::Point) -> Vec<u8>;
    fn deserialize_public_key(pkXm: &[u8]) -> Self::Point;

    fn base_mult(sk: &Self::Scalar) -> Self::Point;
    fn dh(sk: &Self::Scalar, pk: &Self::Point) -> Vec<u8>;
}

pub struct P256;

impl Curve for P256 {
    const N_ID: u16 = 0x0010;
    const SUITE_ID: &[u8] = b"KEM\x00\x10";
    const SECRET_SIZE: usize = 32;
    const SCALAR_SIZE: usize = 32;
    const POINT_SIZE: usize = 65;

    type Scalar = p256::ecdh::EphemeralSecret;
    type Point = p256::PublicKey;

    fn generate_key_pair(rng: &mut impl CryptoRngCore) -> (Self::Scalar, Self::Point) {
        let dk = p256::ecdh::EphemeralSecret::random(rng);
        let ek = dk.public_key();
        (dk, ek)
    }

    fn derive_key_pair(ikm: &[u8]) -> (Self::Scalar, Self::Point) {
        todo!()
    }

    fn serialize_public_key(pkX: &Self::Point) -> Vec<u8> {
        p256::EncodedPoint::from(pkX).as_bytes().to_vec()
    }

    fn deserialize_public_key(pkXm: &[u8]) -> Self::Point {
        p256::PublicKey::from_sec1_bytes(pkXm).unwrap()
    }

    fn base_mult(sk: &Self::Scalar) -> Self::Point {
        sk.public_key()
    }

    fn dh(sk: &Self::Scalar, pk: &Self::Point) -> Vec<u8> {
        sk.diffie_hellman(pk).raw_secret_bytes().to_vec()
    }
}

pub struct P384;

impl Curve for P384 {
    const N_ID: u16 = 0x0011;
    const SUITE_ID: &[u8] = b"KEM\x00\x11";
    const SECRET_SIZE: usize = 48;
    const SCALAR_SIZE: usize = 48;
    const POINT_SIZE: usize = 97;

    type Scalar = p384::ecdh::EphemeralSecret;
    type Point = p384::PublicKey;

    fn generate_key_pair(rng: &mut impl CryptoRngCore) -> (Self::Scalar, Self::Point) {
        let dk = p384::ecdh::EphemeralSecret::random(rng);
        let ek = dk.public_key();
        (dk, ek)
    }

    fn derive_key_pair(ikm: &[u8]) -> (Self::Scalar, Self::Point) {
        todo!()
    }

    fn serialize_public_key(pkX: &Self::Point) -> Vec<u8> {
        p384::EncodedPoint::from(pkX).as_bytes().to_vec()
    }

    fn deserialize_public_key(pkXm: &[u8]) -> Self::Point {
        p384::PublicKey::from_sec1_bytes(pkXm).unwrap()
    }

    fn base_mult(sk: &Self::Scalar) -> Self::Point {
        sk.public_key()
    }

    fn dh(sk: &Self::Scalar, pk: &Self::Point) -> Vec<u8> {
        sk.diffie_hellman(pk).raw_secret_bytes().to_vec()
    }
}

pub struct P521;

impl Curve for P521 {
    const N_ID: u16 = 0x0012;
    const SUITE_ID: &[u8] = b"KEM\x00\x10";
    const SECRET_SIZE: usize = 64;
    const SCALAR_SIZE: usize = 66;
    const POINT_SIZE: usize = 133;

    type Scalar = p521::ecdh::EphemeralSecret;
    type Point = p521::PublicKey;

    fn generate_key_pair(rng: &mut impl CryptoRngCore) -> (Self::Scalar, Self::Point) {
        let dk = p521::ecdh::EphemeralSecret::random(rng);
        let ek = dk.public_key();
        (dk, ek)
    }

    fn derive_key_pair(ikm: &[u8]) -> (Self::Scalar, Self::Point) {
        todo!()
    }

    fn serialize_public_key(pkX: &Self::Point) -> Vec<u8> {
        p521::EncodedPoint::from(pkX).as_bytes().to_vec()
    }

    fn deserialize_public_key(pkXm: &[u8]) -> Self::Point {
        p521::PublicKey::from_sec1_bytes(pkXm).unwrap()
    }

    fn base_mult(sk: &Self::Scalar) -> Self::Point {
        sk.public_key()
    }

    fn dh(sk: &Self::Scalar, pk: &Self::Point) -> Vec<u8> {
        sk.diffie_hellman(pk).raw_secret_bytes().to_vec()
    }
}

pub struct X25519;

impl Curve for X25519 {
    const N_ID: u16 = 0x0020;
    const SUITE_ID: &[u8] = b"KEM\x00\x20";
    const SECRET_SIZE: usize = 32;
    const SCALAR_SIZE: usize = 32;
    const POINT_SIZE: usize = 32;

    type Scalar = x25519_dalek::StaticSecret;
    type Point = x25519_dalek::PublicKey;

    fn generate_key_pair(rng: &mut impl CryptoRngCore) -> (Self::Scalar, Self::Point) {
        let dk = x25519_dalek::StaticSecret::random_from_rng(&mut *rng);
        let ek = x25519_dalek::PublicKey::from(&dk);
        (dk, ek)
    }

    fn derive_key_pair(ikm: &[u8]) -> (Self::Scalar, Self::Point) {
        todo!()
    }

    fn serialize_public_key(pkX: &Self::Point) -> Vec<u8> {
        pkX.as_bytes().to_vec()
    }

    fn deserialize_public_key(pkXm: &[u8]) -> Self::Point {
        let mut pkXb = [0u8; 32];
        pkXb.copy_from_slice(pkXm);
        pkXb.into()
    }

    fn base_mult(sk: &Self::Scalar) -> Self::Point {
        x25519_dalek::PublicKey::from(sk)
    }

    fn dh(sk: &Self::Scalar, pk: &Self::Point) -> Vec<u8> {
        sk.diffie_hellman(pk).as_bytes().to_vec()
    }
}

pub struct X448;

impl Curve for X448 {
    const N_ID: u16 = 0x0021;
    const SUITE_ID: &[u8] = b"KEM\x00\x21";
    const SECRET_SIZE: usize = 64;
    const SCALAR_SIZE: usize = 56;
    const POINT_SIZE: usize = 56;

    type Scalar = x448::Secret;
    type Point = x448::PublicKey;

    fn generate_key_pair(rng: &mut impl CryptoRngCore) -> (Self::Scalar, Self::Point) {
        // Can't use x448::Secret::new because of a trait mismatch
        let mut dk = [0; 56];
        rng.fill_bytes(&mut dk);
        let dk = x448::Secret::from(dk);
        let ek = x448::PublicKey::from(&dk);
        (dk, ek)
    }

    fn derive_key_pair(ikm: &[u8]) -> (Self::Scalar, Self::Point) {
        todo!()
    }

    fn serialize_public_key(pkX: &Self::Point) -> Vec<u8> {
        pkX.as_bytes().to_vec()
    }

    fn deserialize_public_key(pkXm: &[u8]) -> Self::Point {
        x448::PublicKey::from_bytes(pkXm).unwrap()
    }

    fn base_mult(sk: &Self::Scalar) -> Self::Point {
        x448::PublicKey::from(sk)
    }

    fn dh(sk: &Self::Scalar, pk: &Self::Point) -> Vec<u8> {
        sk.as_diffie_hellman(pk).unwrap().as_bytes().to_vec()
    }
}

pub struct Dhkem<C, H>
where
    C: Curve,
    H: Kdf,
{
    _curve: core::marker::PhantomData<C>,
    _kdf: core::marker::PhantomData<H>,
}

impl<C, H> Dhkem<C, H>
where
    C: Curve,
    H: Kdf,
{
    fn extract_and_expand(dh: &[u8], kem_context: &[u8]) -> Vec<u8> {
        let eae_prk = H::labeled_extract(C::SUITE_ID, b"", b"eae_prk", &dh);
        H::labeled_expand(
            C::SUITE_ID,
            &eae_prk,
            b"shared_secret",
            &kem_context,
            Self::N_SECRET,
        )
    }
}

impl<C, H> Kem for Dhkem<C, H>
where
    C: Curve,
    H: Kdf,
{
    const ID: [u8; 2] = C::N_ID.to_be_bytes();

    const N_SECRET: usize = C::SECRET_SIZE;
    const N_ENC: usize = C::POINT_SIZE;
    const N_PK: usize = C::POINT_SIZE;
    const N_SK: usize = C::SCALAR_SIZE;

    type EncapsulationKey = C::Point;
    type DecapsulationKey = C::Scalar;
    type Ciphertext = Vec<u8>;

    fn generate_key_pair(
        rng: &mut impl CryptoRngCore,
    ) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        C::generate_key_pair(rng)
    }

    fn derive_key_pair(ikm: &[u8]) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        C::derive_key_pair(ikm)
    }

    fn serialize_public_key(pkX: &Self::EncapsulationKey) -> Vec<u8> {
        C::serialize_public_key(pkX)
    }

    fn deserialize_public_key(pkXm: &[u8]) -> Self::EncapsulationKey {
        C::deserialize_public_key(pkXm)
    }

    fn encap(
        rng: &mut impl CryptoRngCore,
        pkR: &Self::EncapsulationKey,
    ) -> (Vec<u8>, Self::Ciphertext) {
        use crate::concat;

        let (skE, pkE) = Self::generate_key_pair(rng);
        let dh = C::dh(&skE, pkR);
        let enc = Self::serialize_public_key(&pkE);

        let pkRm = Self::serialize_public_key(pkR);
        let kem_context = concat(&[&enc, &pkRm]);

        let shared_secret = Self::extract_and_expand(&dh, &kem_context);
        (shared_secret, enc)
    }

    fn decap(enc: &Self::Ciphertext, skR: &Self::DecapsulationKey) -> Vec<u8> {
        use crate::concat;

        let pkE = Self::deserialize_public_key(&enc);
        let dh = C::dh(skR, &pkE);

        let pkRm = Self::serialize_public_key(&C::base_mult(skR));
        let kem_context = concat(&[&enc, &pkRm]);

        let shared_secret = Self::extract_and_expand(&dh, &kem_context);
        shared_secret
    }
}

pub type DhkemP256HkdfSha256 = Dhkem<P256, HkdfSha256>;
pub type DhkemP384HkdfSha384 = Dhkem<P384, HkdfSha384>;
pub type DhkemP521HkdfSha512 = Dhkem<P521, HkdfSha512>;
pub type DhkemX25519HkdfSha256 = Dhkem<X25519, HkdfSha256>;
pub type DhkemX448HkdfSha512 = Dhkem<X448, HkdfSha512>;

pub struct MlKem768;

impl Kem for MlKem768 {
    const ID: [u8; 2] = [0x00, 0x41];

    const N_SECRET: usize = 32;
    const N_ENC: usize = 1088;
    const N_PK: usize = 1184;
    const N_SK: usize = 64;

    type EncapsulationKey = <ml_kem::MlKem768 as ml_kem::KemCore>::EncapsulationKey;
    type DecapsulationKey = <ml_kem::MlKem768 as ml_kem::KemCore>::DecapsulationKey;
    type Ciphertext = ml_kem::Ciphertext<ml_kem::MlKem768>;

    fn generate_key_pair(
        rng: &mut impl CryptoRngCore,
    ) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        <ml_kem::MlKem768 as ml_kem::KemCore>::generate(rng)
    }

    fn derive_key_pair(ikm: &[u8]) -> (Self::DecapsulationKey, Self::EncapsulationKey) {
        todo!();
    }

    fn serialize_public_key(pkX: &Self::EncapsulationKey) -> Vec<u8> {
        use ml_kem::EncodedSizeUser;
        pkX.as_bytes().to_vec()
    }

    fn deserialize_public_key(pkXm: &[u8]) -> Self::EncapsulationKey {
        use ml_kem::EncodedSizeUser;
        let enc = ml_kem::Encoded::<Self::EncapsulationKey>::try_from(pkXm).unwrap();
        Self::EncapsulationKey::from_bytes(&enc)
    }

    fn encap(
        rng: &mut impl CryptoRngCore,
        pkR: &Self::EncapsulationKey,
    ) -> (Vec<u8>, Self::Ciphertext) {
        use ml_kem::kem::Encapsulate;
        let (ct, ss) = pkR.encapsulate(rng).unwrap();
        (ss.to_vec(), ct)
    }

    fn decap(enc: &Self::Ciphertext, skR: &Self::DecapsulationKey) -> Vec<u8> {
        use ml_kem::kem::Decapsulate;
        let ss = skR.decapsulate(enc).unwrap();
        ss.to_vec()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn test<K>()
    where
        K: Kem,
    {
        let mut rng = rand::thread_rng();

        let (dk, ek) = K::generate_key_pair(&mut rng);

        let ekm = K::serialize_public_key(&ek);
        assert_eq!(ekm.len(), K::N_PK);

        let (ss_s, ct) = K::encap(&mut rng, &ek);
        let ss_r = K::decap(&ct, &dk);
        assert_eq!(ss_s, ss_r);
        assert_eq!(ss_s.len(), K::N_SECRET);
    }

    #[test]
    fn test_all() {
        test::<DhkemP256HkdfSha256>();
        test::<DhkemP384HkdfSha384>();
        test::<DhkemP521HkdfSha512>();
        test::<DhkemX25519HkdfSha256>();
        test::<DhkemX448HkdfSha512>();
        test::<MlKem768>();
    }
}
