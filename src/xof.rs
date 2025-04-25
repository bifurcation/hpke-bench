pub trait Xof: Default + Clone {
    const ID: [u8; 2];

    fn absorb(&mut self, data: &[u8]);
    fn squeeze(&mut self, len: usize) -> Vec<u8>;

    fn labeled(suite_id: &[u8]) -> Self {
        let mut xof = Self::default();
        xof.absorb(b"HPKE-v1");
        xof.absorb(suite_id);
        xof
    }

    fn length_prefixed_absorb(&mut self, data: &[u8]) {
        use crate::i2osp;
        assert!(data.len() < (1 << 16));
        self.absorb(&i2osp(data.len(), 2));
        self.absorb(data);
    }
}

use sha3::digest::{Update, XofReader};

#[derive(Clone)]
pub enum Shake128 {
    Absorbing(sha3::Shake128),
    Squeezing(sha3::Shake128Reader),
}

impl Default for Shake128 {
    fn default() -> Self {
        Shake128::Absorbing(sha3::Shake128::default())
    }
}

impl Xof for Shake128 {
    const ID: [u8; 2] = [0x00, 0x02];

    fn absorb(&mut self, data: &[u8]) {
        match self {
            Self::Absorbing(xof) => xof.update(data),
            Self::Squeezing(_) => unreachable!(),
        }
    }

    fn squeeze(&mut self, len: usize) -> Vec<u8> {
        match self {
            Self::Absorbing(_) => unreachable!(),
            Self::Squeezing(xof) => {
                let mut data = vec![0; len];
                xof.read(&mut data);
                data
            }
        }
    }
}

#[derive(Clone)]
pub enum TurboShake128 {
    Absorbing(sha3::TurboShake128),
    Squeezing(sha3::TurboShake128Reader),
}

impl Default for TurboShake128 {
    fn default() -> Self {
        TurboShake128::Absorbing(sha3::TurboShake128::from_core(
            sha3::TurboShake128Core::new(0x06),
        ))
    }
}

impl Xof for TurboShake128 {
    const ID: [u8; 2] = [0x00, 0x02];

    fn absorb(&mut self, data: &[u8]) {
        match self {
            Self::Absorbing(xof) => xof.update(data),
            Self::Squeezing(_) => unreachable!(),
        }
    }

    fn squeeze(&mut self, len: usize) -> Vec<u8> {
        match self {
            Self::Absorbing(_) => unreachable!(),
            Self::Squeezing(xof) => {
                let mut data = vec![0; len];
                xof.read(&mut data);
                data
            }
        }
    }
}
