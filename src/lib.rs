//! A collection of encrypted IO handles.

use std::convert::Infallible;

pub mod block;
pub mod full;

pub(crate) type Key<const N: usize> = [u8; N];

pub trait IvGenerator {
    type Error;

    fn generate_iv(&mut self, iv: &mut [u8]) -> Result<(), Self::Error>;
}

pub struct SequentialIvGenerator {
    counter: Vec<u8>,
}

impl SequentialIvGenerator {
    pub fn new(iv_len: usize) -> Self {
        Self {
            counter: vec![0; iv_len],
        }
    }

    fn inc(&mut self) {
        for byte in self.counter.iter_mut() {
            if *byte == u8::MAX {
                *byte = 0;
            } else {
                *byte += 1;
                break;
            }
        }
    }
}

impl IvGenerator for SequentialIvGenerator {
    type Error = Infallible;

    fn generate_iv(&mut self, iv: &mut [u8]) -> Result<(), Self::Error> {
        assert!(iv.len() >= self.counter.len(), "incorrect IV length");
        iv.copy_from_slice(&self.counter);
        self.inc();
        Ok(())
    }
}
