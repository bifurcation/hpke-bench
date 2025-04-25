pub trait Kem {
    const ID: [u8; 2];
    const N_SECRET: usize;
    const N_ENC: usize;
    const N_PK: usize;
    const N_SK: usize;

    type EncapsulationKey;
    type DecapsulationKey;
    type Ciphertext;

    fn generate_key_pair(/* todo */) -> (Self::DecapsulationKey, Self::EncapsulationKey);
    fn derive_key_pair(ikm: &[u8]) -> (Self::DecapsulationKey, Self::EncapsulationKey);
    fn serialize_public_key(pkX: &Self::EncapsulationKey) -> Vec<u8>;
    fn deserialize_public_key(pkXm: &[u8]) -> Self::EncapsulationKey;

    fn encap(pkR: &Self::EncapsulationKey) -> (Vec<u8>, Self::Ciphertext);
    fn decap(enc: &Self::Ciphertext, skR: &Self::DecapsulationKey) -> Vec<u8>;
}
