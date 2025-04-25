pub trait Xof: Default + Clone {
    const ID: [u8; 2];
    const N_H: usize;

    fn absorb(&mut self, data: &[u8]) -> &mut Self;
    fn squeeze(&mut self, len: usize) -> Vec<u8>;

    fn labeled(suite_id: &[u8]) -> Self {
        let mut xof = Self::default();
        xof.absorb(b"HPKE-v1");
        xof.absorb(suite_id);
        xof
    }

    fn length_prefixed_absorb(&mut self, data: &[u8]) -> &mut Self {
        use crate::i2osp;
        assert!(data.len() < (1 << 16));
        self.absorb(&i2osp(data.len(), 2));
        self.absorb(data);

        self
    }
}

use sha3::digest::{ExtendableOutput, Update, XofReader};

#[derive(Clone)]
pub enum Shake128State {
    Absorbing(sha3::Shake128),
    Squeezing(sha3::Shake128Reader),
}

#[derive(Clone)]
pub struct Shake128(Shake128State);

impl Default for Shake128 {
    fn default() -> Self {
        Self(Shake128State::Absorbing(sha3::Shake128::default()))
    }
}

impl Xof for Shake128 {
    const ID: [u8; 2] = [0x00, 0x02];
    const N_H: usize = 32;

    fn absorb(&mut self, data: &[u8]) -> &mut Self {
        match self.0 {
            Shake128State::Absorbing(ref mut xof) => xof.update(data),
            Shake128State::Squeezing(_) => unreachable!(),
        }

        self
    }

    fn squeeze(&mut self, len: usize) -> Vec<u8> {
        match &mut self.0 {
            Shake128State::Absorbing(xof) => {
                let reader = xof.clone().finalize_xof();
                self.0 = Shake128State::Squeezing(reader);
                self.squeeze(len)
            }
            Shake128State::Squeezing(reader) => {
                let mut data = vec![0; len];
                reader.read(&mut data);
                data
            }
        }
    }
}

#[derive(Clone)]
pub enum TurboShake128State {
    Absorbing(sha3::TurboShake128),
    Squeezing(sha3::TurboShake128Reader),
}

#[derive(Clone)]
pub struct TurboShake128(TurboShake128State);

impl Default for TurboShake128 {
    fn default() -> Self {
        Self(TurboShake128State::Absorbing(
            sha3::TurboShake128::from_core(sha3::TurboShake128Core::new(0x06)),
        ))
    }
}

impl Xof for TurboShake128 {
    const ID: [u8; 2] = [0x00, 0x02];
    const N_H: usize = 32;

    fn absorb(&mut self, data: &[u8]) -> &mut Self {
        match self.0 {
            TurboShake128State::Absorbing(ref mut xof) => xof.update(data),
            TurboShake128State::Squeezing(_) => unreachable!(),
        }

        self
    }

    fn squeeze(&mut self, len: usize) -> Vec<u8> {
        match &mut self.0 {
            TurboShake128State::Absorbing(xof) => {
                let reader = xof.clone().finalize_xof();
                self.0 = TurboShake128State::Squeezing(reader);
                self.squeeze(len)
            }
            TurboShake128State::Squeezing(reader) => {
                let mut data = vec![0; len];
                reader.read(&mut data);
                data
            }
        }
    }
}
