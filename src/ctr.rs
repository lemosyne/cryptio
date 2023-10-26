//! Experimental
use std::marker::PhantomData;

use crate::Key;
use crypter::Crypter;
use embedded_io::{
    blocking::{Read, Seek, Write},
    Io, SeekFrom,
};
use kms::KeyManagementScheme;
use rand::{CryptoRng, Rng, RngCore};

pub struct BlockIvCtrCryptIo<'a, IO, KMS, R, C, const BLK_SZ: usize, const KEY_SZ: usize> {
    io: IO,
    kms: &'a mut KMS,
    rng: R,
    pd: PhantomData<C>,
}

impl<'a, IO, KMS, R, C, const BLK_SZ: usize, const KEY_SZ: usize>
    BlockIvCtrCryptIo<'a, IO, KMS, R, C, BLK_SZ, KEY_SZ>
where
    IO: Seek,
    R: RngCore + CryptoRng,
    C: Crypter,
{
    pub fn new(io: IO, kms: &'a mut KMS, rng: R) -> Self {
        Self {
            io,
            kms,
            rng,
            pd: PhantomData,
        }
    }

    fn curr_offset(&mut self) -> Result<usize, IO::Error> {
        self.io.stream_position().map(|offset| offset as usize)
    }
}

impl<'a, IO, KMS, R, C, const BLK_SZ: usize, const KEY_SZ: usize> Io
    for BlockIvCtrCryptIo<'a, IO, KMS, R, C, BLK_SZ, KEY_SZ>
where
    IO: Io,
{
    type Error = IO::Error;
}

impl<'a, IO, KMS, R, C, const BLK_SZ: usize, const KEY_SZ: usize> Read
    for BlockIvCtrCryptIo<'a, IO, KMS, R, C, BLK_SZ, KEY_SZ>
where
    IO: Read + Seek,
    KMS: KeyManagementScheme<KeyId = u64, Key = Key<KEY_SZ>>,
    R: RngCore + CryptoRng,
    C: Crypter,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        // Track the bytes we've and we need to read.
        let mut total = 0;
        let mut size = buf.len();

        // Eases the tracking of where we are in the stream.
        let origin = self.curr_offset()?;
        let mut offset = origin;

        while size > 0 {}

        Ok(total)
    }
}
