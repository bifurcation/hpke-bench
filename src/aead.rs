pub trait Aead {
    const ID: [u8; 2];
    const N_K: usize;
    const N_N: usize;
    const N_T: usize;

    fn seal(key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8], ct: &mut [u8]);
    fn open(key: &[u8], nonce: &[u8], aad: &[u8], ct: &[u8], pt: &mut [u8]);
}
