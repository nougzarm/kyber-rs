use sha3::{Shake128, digest::{ExtendableOutput, Update, XofReader}};

pub trait XOF {
    fn new() -> Self;

    fn absorb(&mut self, bytes: Vec<u8>);

    fn squeeze(&mut self, length: usize) -> Vec<u8>;
}

pub enum SHAKE128 {
    Absorbing(Shake128),
    Squeezing(Box<dyn XofReader>),
}

impl XOF for SHAKE128 {
    fn new() -> Self {
        SHAKE128::Absorbing(Shake128::default())
    }

    fn absorb(&mut self, bytes: Vec<u8>) {
        self.0.update(&bytes);
    }

    fn squeeze(&mut self, length: usize) -> Vec<u8> {
        let mut output = vec![0u8; length];
        self.0.finalize_xof(&mut output);
        output
    }
}