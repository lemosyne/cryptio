use crate::{IvGenerator, Key};
use crypter::StatefulCrypter;
use embedded_io::{
    blocking::{Read, ReadAt, Seek, Write, WriteAt},
    Io, SeekFrom,
};
use kms::KeyManagementScheme;

pub enum Block {
    Empty,
    Unaligned { real: usize, fill: usize },
    Aligned { real: usize },
}

pub struct BlockIvCryptIo<'a, IO, KMS, G, C, const BLK_SZ: usize, const KEY_SZ: usize> {
    io: IO,
    kms: &'a mut KMS,
    ivgen: &'a mut G,
    crypter: &'a mut C,
}

impl<'a, IO, KMS, G, C, const BLK_SZ: usize, const KEY_SZ: usize>
    BlockIvCryptIo<'a, IO, KMS, G, C, BLK_SZ, KEY_SZ>
where
    IO: Io,
    G: IvGenerator,
    C: StatefulCrypter,
{
    /// Constructs a new `BlockIvCryptoIo`.
    pub fn new(io: IO, kms: &'a mut KMS, ivg: &'a mut G, crypter: &'a mut C) -> Self
    where
        C: Default,
    {
        Self {
            io,
            kms,
            ivgen: ivg,
            crypter,
        }
    }

    /// Returns if `offset` is aligned to a block boundary.
    fn offset_is_aligned(&self, offset: usize) -> bool {
        self.offset_padding(offset) == 0
    }

    /// Returns the block that `offset` falls under.
    fn offset_block(&self, offset: usize) -> usize {
        offset / BLK_SZ
    }

    /// Returns the size of a padded block.
    fn padded_block_size(&self) -> usize {
        BLK_SZ + C::iv_length()
    }

    /// Returns `offset` aligned to the start of its block.
    fn offset_aligned(&self, offset: usize) -> usize {
        (offset / BLK_SZ) * self.padded_block_size()
    }

    /// Returns the distance from `offset` to the start of its block.
    fn offset_padding(&self, offset: usize) -> usize {
        offset % BLK_SZ
    }

    /// Returns the distance from `offset` to the end of the IV at the start of its block.
    fn offset_fill(&self, offset: usize) -> usize {
        offset - (self.offset_block(offset) * BLK_SZ)
    }

    /// Returns our current offset.
    fn curr_offset(&mut self) -> Result<usize, IO::Error>
    where
        IO: Seek,
    {
        self.io.stream_position().map(|offset| offset as usize)
    }

    /// Reads a block from a given offset.
    fn read_block(&mut self, offset: usize, buf: &mut [u8]) -> Result<Block, IO::Error>
    where
        IO: Read + Seek,
    {
        let aligned = self.offset_aligned(offset);
        let padding = self.offset_padding(offset);
        let fill = self.offset_fill(offset);

        self.io.seek(SeekFrom::Start(aligned as u64))?;

        let nbytes = self.io.read(buf)?;

        // Restore seek cursor if we didn't read anything.
        if nbytes == 0 || nbytes < padding + C::iv_length() {
            self.io.seek(SeekFrom::Start(offset as u64))?;
            return Ok(Block::Empty);
        }

        // The real data size (doesn't include IV).
        let real = nbytes - C::iv_length();

        if padding == 0 {
            Ok(Block::Aligned { real })
        } else {
            Ok(Block::Unaligned { real, fill })
        }
    }

    /// Reads a block from a given offset.
    fn read_block_at(&mut self, offset: usize, buf: &mut [u8]) -> Result<Block, IO::Error>
    where
        IO: ReadAt,
    {
        let aligned = self.offset_aligned(offset);
        let padding = self.offset_padding(offset);
        let fill = self.offset_fill(offset);

        let nbytes = self.io.read_at(buf, aligned as u64)?;

        // Restore seek cursor if we didn't read anything.
        if nbytes == 0 || nbytes < padding + C::iv_length() {
            return Ok(Block::Empty);
        }

        // The real data size (doesn't include IV).
        let real = nbytes - C::iv_length();

        if padding == 0 {
            Ok(Block::Aligned { real })
        } else {
            Ok(Block::Unaligned { real, fill })
        }
    }

    /// Writes a block with a prepended IV to a given offset.
    fn write_block(&mut self, offset: usize, iv: &[u8], data: &[u8]) -> Result<usize, IO::Error>
    where
        IO: Write + Seek,
    {
        let aligned = self.offset_aligned(offset);
        self.io.seek(SeekFrom::Start(aligned as u64))?;
        self.io.write(&iv)?;
        Ok(self.io.write(&data)?)
    }

    /// Writes a block with a prepended IV to a given offset.
    fn write_block_at(&mut self, offset: usize, iv: &[u8], data: &[u8]) -> Result<usize, IO::Error>
    where
        IO: WriteAt,
    {
        let aligned = self.offset_aligned(offset);
        self.io.write_at(iv, aligned as u64)?;
        Ok(self.io.write_at(data, (aligned + iv.len()) as u64)?)
    }
}

impl<IO, KMS, R, C, const BLK_SZ: usize, const KEY_SZ: usize> Io
    for BlockIvCryptIo<'_, IO, KMS, R, C, BLK_SZ, KEY_SZ>
where
    IO: Io,
{
    type Error = IO::Error;
}

impl<IO, KMS, G, C, const BLK_SZ: usize, const KEY_SZ: usize> Read
    for BlockIvCryptIo<'_, IO, KMS, G, C, BLK_SZ, KEY_SZ>
where
    IO: Read + Seek,
    KMS: KeyManagementScheme<KeyId = u64, Key = Key<KEY_SZ>>,
    G: IvGenerator,
    C: StatefulCrypter,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        // Track the bytes we've read and we need to read.
        let mut total = 0;
        let mut size = buf.len();

        // Easier to track where we are in the stream.
        let origin = self.curr_offset()?;
        let mut offset = origin;

        // Scratch data buffer.
        let mut scratch = vec![0; self.padded_block_size()];

        while size > 0 {
            match self.read_block(offset, &mut scratch)? {
                Block::Empty => {
                    break;
                }
                Block::Unaligned { real, fill } => {
                    let block = self.offset_block(offset);
                    let (iv, data) = scratch.split_at_mut(C::iv_length());

                    // Decrypt the bytes we read.
                    let key = self.kms.derive(block as u64).map_err(|_| ()).unwrap();

                    self.crypter
                        .decrypt(&key, iv, data)
                        .map_err(|_| ())
                        .unwrap();

                    // Calculate the number of bytes we've actually read and copy those bytes in.
                    let nbytes = size.min(real - fill);
                    if nbytes == 0 {
                        break;
                    }

                    buf[total..total + nbytes].copy_from_slice(&data[fill..fill + nbytes]);

                    size -= nbytes;
                    offset += nbytes;
                    total += nbytes;
                }
                Block::Aligned { real } => {
                    let block = self.offset_block(offset);
                    let (iv, data) = scratch.split_at_mut(C::iv_length());

                    // Decrypt the bytes we read.
                    let key = self.kms.derive(block as u64).map_err(|_| ()).unwrap();

                    self.crypter
                        .decrypt(&key, iv, data)
                        .map_err(|_| ())
                        .unwrap();

                    // Copy in the decrypted bytes.
                    let nbytes = size.min(real);
                    if nbytes == 0 {
                        break;
                    }

                    buf[total..total + nbytes].copy_from_slice(&data[..nbytes]);

                    size -= nbytes;
                    offset += nbytes;
                    total += nbytes;
                }
            }
        }

        self.io.seek(SeekFrom::Start((origin + total) as u64))?;

        Ok(total)
    }
}

impl<IO, KMS, G, C, const BLK_SZ: usize, const KEY_SZ: usize> ReadAt
    for BlockIvCryptIo<'_, IO, KMS, G, C, BLK_SZ, KEY_SZ>
where
    IO: ReadAt,
    KMS: KeyManagementScheme<KeyId = u64, Key = Key<KEY_SZ>>,
    G: IvGenerator,
    C: StatefulCrypter,
{
    fn read_at(&mut self, buf: &mut [u8], offset: u64) -> Result<usize, Self::Error> {
        // Track the bytes we've read and we need to read.
        let mut total = 0;
        let mut size = buf.len();
        let mut offset = offset as usize;

        // Scratch data buffer.
        let mut scratch = vec![0; self.padded_block_size()];

        while size > 0 {
            match self.read_block_at(offset, &mut scratch)? {
                Block::Empty => {
                    break;
                }
                Block::Unaligned { real, fill } => {
                    let block = self.offset_block(offset);
                    let (iv, data) = scratch.split_at_mut(C::iv_length());

                    // Decrypt the bytes we read.
                    let key = self.kms.derive(block as u64).map_err(|_| ()).unwrap();

                    self.crypter
                        .decrypt(&key, iv, data)
                        .map_err(|_| ())
                        .unwrap();

                    // Calculate the number of bytes we've actually read and copy those bytes in.
                    let nbytes = size.min(real - fill);
                    if nbytes == 0 {
                        break;
                    }

                    buf[total..total + nbytes].copy_from_slice(&data[fill..fill + nbytes]);

                    size -= nbytes;
                    offset += nbytes;
                    total += nbytes;
                }
                Block::Aligned { real } => {
                    let block = self.offset_block(offset);
                    let (iv, data) = scratch.split_at_mut(C::iv_length());

                    // Decrypt the bytes we read.
                    let key = self.kms.derive(block as u64).map_err(|_| ()).unwrap();

                    self.crypter
                        .decrypt(&key, iv, data)
                        .map_err(|_| ())
                        .unwrap();

                    // Copy in the decrypted bytes.
                    let nbytes = size.min(real);
                    if nbytes == 0 {
                        break;
                    }

                    buf[total..total + nbytes].copy_from_slice(&data[..nbytes]);

                    size -= nbytes;
                    offset += nbytes;
                    total += nbytes;
                }
            }
        }

        Ok(total)
    }
}

impl<IO, KMS, G, C, const BLK_SZ: usize, const KEY_SZ: usize> Write
    for BlockIvCryptIo<'_, IO, KMS, G, C, BLK_SZ, KEY_SZ>
where
    IO: Read + Write + Seek,
    KMS: KeyManagementScheme<KeyId = u64, Key = Key<KEY_SZ>>,
    G: IvGenerator,
    C: StatefulCrypter,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        // Track the bytes we've written and we need to write.
        let mut total = 0;
        let mut size = buf.len();

        // Easier to track where we are in the stream.
        let origin = self.curr_offset()?;
        let mut offset = origin;

        // Scratch data buffers.
        let mut scratch = vec![0; self.padded_block_size()];
        let mut scratch_block = vec![0; BLK_SZ];

        while size > 0 {
            // If we aren't block-aligned, then we need to rewrite the bytes preceding our current
            // offset in the block.
            if !self.offset_is_aligned(offset) {
                match self.read_block(offset, &mut scratch)? {
                    // There should be something there, but we didn't read anything.
                    Block::Empty => {
                        self.io.seek(SeekFrom::Start(origin as u64))?;
                        return Ok(total);
                    }
                    Block::Unaligned { real, fill } => {
                        let block = self.offset_block(offset);
                        let (iv, data) = scratch.split_at_mut(C::iv_length());

                        // Decrypt the bytes we read.
                        let key = self.kms.derive(block as u64).map_err(|_| ()).unwrap();
                        self.crypter
                            .decrypt(&key, iv, &mut data[..real])
                            .map_err(|_| ())
                            .unwrap();

                        // Add in the bytes that we're writing, up until a block boundary.
                        let rest = size.min(data.len() - fill);
                        data[fill..fill + rest].copy_from_slice(&buf[total..total + rest]);

                        // Generate a new IV.
                        self.ivgen.generate_iv(iv).map_err(|_| ()).unwrap();
                        let key = self.kms.update(block as u64).map_err(|_| ()).unwrap();
                        self.crypter
                            .encrypt(&key, iv, data)
                            .map_err(|_| ())
                            .unwrap();

                        // Write the IV and ciphertext.
                        // The amount of bytes could exceed what was there originally (real).
                        let amount = real.max(fill + rest);
                        let nbytes = self.write_block(offset, &iv, &data[..amount])?;
                        let written = rest.min(nbytes - fill);
                        if nbytes == 0 || written == 0 {
                            self.io.seek(SeekFrom::Start(origin as u64))?;
                            return Ok(0);
                        }

                        size -= written;
                        offset += written;
                        total += written;
                    }
                    _ => {
                        panic!("shouldn't have gotten a block-aligned read")
                    }
                }
            } else if size > BLK_SZ {
                let block = self.offset_block(offset);
                let (iv, _data) = scratch.split_at_mut(C::iv_length());

                // Copy data to a scratch block buffer for encryption.
                scratch_block.copy_from_slice(&buf[total..total + BLK_SZ]);

                // Encrypt the data with a new IV.
                self.ivgen.generate_iv(iv).map_err(|_| ()).unwrap();
                let key = self.kms.update(block as u64).map_err(|_| ()).unwrap();
                self.crypter
                    .encrypt(&key, &iv, &mut scratch_block)
                    .map_err(|_| ())
                    .unwrap();

                // Write the IV and ciphertext.
                let nbytes = self.write_block(offset, iv, &scratch_block)?;
                if nbytes == 0 {
                    self.io.seek(SeekFrom::Start((origin + total) as u64))?;
                    return Ok(total);
                }

                total += nbytes;
                offset += nbytes;
                size -= nbytes;
            } else {
                match self.read_block(offset, &mut scratch)? {
                    // Receiving block empty means that there aren't any trailing bytes that we need to
                    // rewrite, so we can just go ahead and write out the remaining bytes.
                    Block::Empty => {
                        let block = self.offset_block(offset);
                        let (iv, _data) = scratch.split_at_mut(C::iv_length());

                        // Copy over the bytes to the scratch buffer for encryption.
                        scratch_block[..size].copy_from_slice(&buf[total..total + size]);

                        // Encrypt the remaining bytes.
                        self.ivgen.generate_iv(iv).map_err(|_| ()).unwrap();
                        let key = self.kms.update(block as u64).map_err(|_| ()).unwrap();

                        self.crypter
                            .encrypt(&key, iv, &mut scratch_block[..size])
                            .map_err(|_| ())
                            .unwrap();

                        // Write the block.
                        let nbytes = self.write_block(offset, iv, &scratch_block[..size])?;

                        total += nbytes;
                        size -= nbytes;
                    }
                    // We need to rewrite any bytes trailing the overwritten bytes.
                    Block::Aligned { real } => {
                        let block = self.offset_block(offset);
                        let (iv, data) = scratch.split_at_mut(C::iv_length());

                        // Decrypt the bytes.
                        let key = self.kms.derive(block as u64).map_err(|_| ()).unwrap();

                        self.crypter
                            .decrypt(&key, iv, data)
                            .map_err(|_| ())
                            .unwrap();

                        // Copy in the bytes that we want to update.
                        data[..size].copy_from_slice(&buf[total..total + size]);

                        // Encrypt the plaintext.
                        self.ivgen.generate_iv(iv).map_err(|_| ()).unwrap();
                        let key = self.kms.update(block as u64).map_err(|_| ()).unwrap();

                        self.crypter
                            .encrypt(&key, iv, data)
                            .map_err(|_| ())
                            .unwrap();

                        // Write the block.
                        let nbytes = size.max(real);
                        self.write_block(offset, iv, &data[..nbytes])?;

                        total += size.min(nbytes);
                        size -= size.min(nbytes);
                    }
                    _ => {
                        panic!("shouldn't be performing an unaligned write");
                    }
                }
            }
        }

        self.io.seek(SeekFrom::Start((origin + total) as u64))?;

        Ok(total)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.io.flush()
    }
}

impl<IO, KMS, G, C, const BLK_SZ: usize, const KEY_SZ: usize> WriteAt
    for BlockIvCryptIo<'_, IO, KMS, G, C, BLK_SZ, KEY_SZ>
where
    IO: ReadAt + WriteAt,
    KMS: KeyManagementScheme<KeyId = u64, Key = Key<KEY_SZ>>,
    G: IvGenerator,
    C: StatefulCrypter,
{
    fn write_at(&mut self, buf: &[u8], offset: u64) -> Result<usize, Self::Error> {
        // Track the bytes we've written and we need to write.
        let mut total = 0;
        let mut size = buf.len();
        let mut offset = offset as usize;

        // Scratch data buffers.
        let mut scratch = vec![0; self.padded_block_size()];
        let mut scratch_block = vec![0; BLK_SZ];

        while size > 0 {
            // If we aren't block-aligned, then we need to rewrite the bytes preceding our current
            // offset in the block.
            if !self.offset_is_aligned(offset) {
                match self.read_block_at(offset, &mut scratch)? {
                    // There should be something there, but we didn't read anything.
                    Block::Empty => {
                        return Ok(total);
                    }
                    Block::Unaligned { real, fill } => {
                        let block = self.offset_block(offset);
                        let (iv, data) = scratch.split_at_mut(C::iv_length());

                        // Decrypt the bytes we read.
                        let key = self.kms.derive(block as u64).map_err(|_| ()).unwrap();
                        self.crypter
                            .decrypt(&key, iv, &mut data[..real])
                            .map_err(|_| ())
                            .unwrap();

                        // Add in the bytes that we're writing, up until a block boundary.
                        let rest = size.min(data.len() - fill);
                        data[fill..fill + rest].copy_from_slice(&buf[total..total + rest]);

                        // Generate a new IV.
                        self.ivgen.generate_iv(iv).map_err(|_| ()).unwrap();
                        let key = self.kms.update(block as u64).map_err(|_| ()).unwrap();
                        self.crypter
                            .encrypt(&key, iv, data)
                            .map_err(|_| ())
                            .unwrap();

                        // Write the IV and ciphertext.
                        // The amount of bytes could exceed what was there originally (real).
                        let amount = real.max(fill + rest);
                        let nbytes = self.write_block_at(offset, &iv, &data[..amount])?;
                        let written = rest.min(nbytes - fill);
                        if nbytes == 0 || written == 0 {
                            return Ok(0);
                        }

                        size -= written;
                        offset += written;
                        total += written;
                    }
                    _ => {
                        panic!("shouldn't have gotten a block-aligned read")
                    }
                }
            } else if size > BLK_SZ {
                let block = self.offset_block(offset);
                let (iv, _data) = scratch.split_at_mut(C::iv_length());

                // Copy data to a scratch block buffer for encryption.
                scratch_block.copy_from_slice(&buf[total..total + BLK_SZ]);

                // Encrypt the data with a new IV.
                self.ivgen.generate_iv(iv).map_err(|_| ()).unwrap();
                let key = self.kms.update(block as u64).map_err(|_| ()).unwrap();
                self.crypter
                    .encrypt(&key, &iv, &mut scratch_block)
                    .map_err(|_| ())
                    .unwrap();

                // Write the IV and ciphertext.
                let nbytes = self.write_block_at(offset, iv, &scratch_block)?;
                if nbytes == 0 {
                    return Ok(total);
                }

                total += nbytes;
                offset += nbytes;
                size -= nbytes;
            } else {
                match self.read_block_at(offset, &mut scratch)? {
                    // Receiving block empty means that there aren't any trailing bytes that we need to
                    // rewrite, so we can just go ahead and write out the remaining bytes.
                    Block::Empty => {
                        let block = self.offset_block(offset);
                        let (iv, _data) = scratch.split_at_mut(C::iv_length());

                        // Copy over the bytes to the scratch buffer for encryption.
                        scratch_block[..size].copy_from_slice(&buf[total..total + size]);

                        // Encrypt the remaining bytes.
                        self.ivgen.generate_iv(iv).map_err(|_| ()).unwrap();
                        let key = self.kms.update(block as u64).map_err(|_| ()).unwrap();

                        self.crypter
                            .encrypt(&key, iv, &mut scratch_block[..size])
                            .map_err(|_| ())
                            .unwrap();

                        // Write the block.
                        let nbytes = self.write_block_at(offset, iv, &scratch_block[..size])?;

                        total += nbytes;
                        size -= nbytes;
                    }
                    // We need to rewrite any bytes trailing the overwritten bytes.
                    Block::Aligned { real } => {
                        let block = self.offset_block(offset);
                        let (iv, data) = scratch.split_at_mut(C::iv_length());

                        // Decrypt the bytes.
                        let key = self.kms.derive(block as u64).map_err(|_| ()).unwrap();

                        self.crypter
                            .decrypt(&key, iv, data)
                            .map_err(|_| ())
                            .unwrap();

                        // Copy in the bytes that we want to update.
                        data[..size].copy_from_slice(&buf[total..total + size]);

                        // Encrypt the plaintext.
                        self.ivgen.generate_iv(iv).map_err(|_| ()).unwrap();
                        let key = self.kms.update(block as u64).map_err(|_| ()).unwrap();

                        self.crypter
                            .encrypt(&key, iv, data)
                            .map_err(|_| ())
                            .unwrap();

                        // Write the block.
                        let nbytes = size.max(real);
                        self.write_block_at(offset, iv, &data[..nbytes])?;

                        total += size.min(nbytes);
                        size -= size.min(nbytes);
                    }
                    _ => {
                        panic!("shouldn't be performing an unaligned write");
                    }
                }
            }
        }

        Ok(total)
    }
}

impl<IO, KMS, R, C, const BLK_SZ: usize, const KEY_SZ: usize> Seek
    for BlockIvCryptIo<'_, IO, KMS, R, C, BLK_SZ, KEY_SZ>
where
    IO: Seek,
{
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, Self::Error> {
        self.io.seek(pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SequentialIvGenerator;
    use anyhow::Result;
    use crypter::openssl::StatefulAes256Ctr;
    use embedded_io::{adapters::FromStd, SeekFrom};
    use hasher::openssl::{Sha3_256, SHA3_256_MD_SIZE};
    use khf::Khf;
    use rand::{rngs::ThreadRng, Rng, RngCore};
    use std::fs::{self, File};
    use tempfile::NamedTempFile;

    const BLOCK_SIZE: usize = 128;
    const KEY_SIZE: usize = SHA3_256_MD_SIZE;

    #[test]
    fn simple() -> Result<()> {
        let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());
        let mut ivg = SequentialIvGenerator::new(16);
        let mut crypter = StatefulAes256Ctr::new();

        let mut blockio = BlockIvCryptIo::<
            FromStd<NamedTempFile>,
            Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
            SequentialIvGenerator,
            StatefulAes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            FromStd::new(NamedTempFile::new()?),
            &mut khf,
            &mut ivg,
            &mut crypter,
        );

        blockio.write_all(&['a' as u8; BLOCK_SIZE])?;

        let mut buf = vec![0; BLOCK_SIZE];
        blockio.seek(SeekFrom::Start(0))?;
        blockio.read_exact(&mut buf)?;

        assert_eq!(&buf[..], &['a' as u8; BLOCK_SIZE]);

        Ok(())
    }

    #[test]
    fn simple_at() -> Result<()> {
        let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());
        let mut ivg = SequentialIvGenerator::new(16);
        let mut crypter = StatefulAes256Ctr::new();

        let mut blockio = BlockIvCryptIo::<
            FromStd<NamedTempFile>,
            Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
            SequentialIvGenerator,
            StatefulAes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            FromStd::new(NamedTempFile::new()?),
            &mut khf,
            &mut ivg,
            &mut crypter,
        );

        blockio.write_all_at(&['a' as u8; BLOCK_SIZE], 0)?;

        let mut buf = vec![0; BLOCK_SIZE];
        blockio.read_exact_at(&mut buf, 0).unwrap();

        assert_eq!(&buf[..], &['a' as u8; BLOCK_SIZE]);

        Ok(())
    }

    // Writes 4 blocks of 'a's, then 4 'b's at offset 3.
    #[test]
    fn offset_write() -> Result<()> {
        let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());
        let mut ivg = SequentialIvGenerator::new(16);
        let mut crypter = StatefulAes256Ctr::new();

        let mut blockio = BlockIvCryptIo::<
            FromStd<NamedTempFile>,
            Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
            SequentialIvGenerator,
            StatefulAes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            FromStd::new(NamedTempFile::new()?),
            &mut khf,
            &mut ivg,
            &mut crypter,
        );

        blockio.write_all(&['a' as u8; 4 * BLOCK_SIZE])?;
        blockio.seek(SeekFrom::Start(3))?;
        blockio.write_all(&['b' as u8; 4])?;

        let mut buf = vec![0; 4 * BLOCK_SIZE];
        blockio.seek(SeekFrom::Start(0))?;
        blockio.read_exact(&mut buf)?;

        assert_eq!(&buf[..3], &['a' as u8; 3]);
        assert_eq!(&buf[3..7], &['b' as u8; 4]);
        assert_eq!(&buf[7..], &['a' as u8; 4 * BLOCK_SIZE - 7]);

        Ok(())
    }

    // Writes 4 blocks of 'a's, then 4 'b's at offset 3.
    #[test]
    fn offset_write_at() -> Result<()> {
        let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());
        let mut ivg = SequentialIvGenerator::new(16);
        let mut crypter = StatefulAes256Ctr::new();

        let mut blockio = BlockIvCryptIo::<
            FromStd<NamedTempFile>,
            Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
            SequentialIvGenerator,
            StatefulAes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            FromStd::new(NamedTempFile::new()?),
            &mut khf,
            &mut ivg,
            &mut crypter,
        );

        blockio.write_all_at(&['a' as u8; 4 * BLOCK_SIZE], 0)?;
        blockio.write_all_at(&['b' as u8; 4], 3)?;

        let mut buf = vec![0; 4 * BLOCK_SIZE];
        blockio.read_exact_at(&mut buf, 0).unwrap();

        assert_eq!(&buf[..3], &['a' as u8; 3]);
        assert_eq!(&buf[3..7], &['b' as u8; 4]);
        assert_eq!(&buf[7..], &['a' as u8; 4 * BLOCK_SIZE - 7]);

        Ok(())
    }

    // Writes 2 blocks of 'a's and a block of 'b' right in the middle.
    #[test]
    fn misaligned_write() -> Result<()> {
        let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());
        let mut ivg = SequentialIvGenerator::new(16);
        let mut crypter = StatefulAes256Ctr::new();

        let mut blockio = BlockIvCryptIo::<
            FromStd<NamedTempFile>,
            Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
            SequentialIvGenerator,
            StatefulAes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            FromStd::new(NamedTempFile::new()?),
            &mut khf,
            &mut ivg,
            &mut crypter,
        );

        blockio.write_all(&['a' as u8; 2 * BLOCK_SIZE])?;
        blockio.seek(SeekFrom::Start((BLOCK_SIZE / 2) as u64))?;
        blockio.write_all(&['b' as u8; BLOCK_SIZE])?;

        let mut buf = vec![0; 2 * BLOCK_SIZE];
        blockio.seek(SeekFrom::Start(0))?;
        blockio.read_exact(&mut buf)?;

        assert_eq!(&buf[..BLOCK_SIZE / 2], &['a' as u8; BLOCK_SIZE / 2]);
        assert_eq!(
            &buf[BLOCK_SIZE / 2..BLOCK_SIZE / 2 + BLOCK_SIZE],
            &['b' as u8; BLOCK_SIZE]
        );
        assert_eq!(
            &buf[BLOCK_SIZE / 2 + BLOCK_SIZE..],
            &['a' as u8; BLOCK_SIZE / 2]
        );

        Ok(())
    }

    // Writes 2 blocks of 'a's and a block of 'b' right in the middle.
    #[test]
    fn misaligned_write_at() -> Result<()> {
        let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());
        let mut ivg = SequentialIvGenerator::new(16);
        let mut crypter = StatefulAes256Ctr::new();

        let mut blockio = BlockIvCryptIo::<
            FromStd<NamedTempFile>,
            Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
            SequentialIvGenerator,
            StatefulAes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            FromStd::new(NamedTempFile::new()?),
            &mut khf,
            &mut ivg,
            &mut crypter,
        );

        blockio.write_all_at(&['a' as u8; 2 * BLOCK_SIZE], 0)?;
        blockio.write_all_at(&['b' as u8; BLOCK_SIZE], (BLOCK_SIZE / 2) as u64)?;

        let mut buf = vec![0; 2 * BLOCK_SIZE];
        blockio.read_exact_at(&mut buf, 0).unwrap();

        assert_eq!(&buf[..BLOCK_SIZE / 2], &['a' as u8; BLOCK_SIZE / 2]);
        assert_eq!(
            &buf[BLOCK_SIZE / 2..BLOCK_SIZE / 2 + BLOCK_SIZE],
            &['b' as u8; BLOCK_SIZE]
        );
        assert_eq!(
            &buf[BLOCK_SIZE / 2 + BLOCK_SIZE..],
            &['a' as u8; BLOCK_SIZE / 2]
        );

        Ok(())
    }
    #[test]
    fn short_write() -> Result<()> {
        let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());
        let mut ivg = SequentialIvGenerator::new(16);
        let mut crypter = StatefulAes256Ctr::new();

        let mut blockio = BlockIvCryptIo::<
            FromStd<NamedTempFile>,
            Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
            SequentialIvGenerator,
            StatefulAes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            FromStd::new(NamedTempFile::new()?),
            &mut khf,
            &mut ivg,
            &mut crypter,
        );

        blockio.write_all(&['a' as u8])?;
        blockio.write_all(&['b' as u8])?;

        let mut buf = vec![0; 2];
        blockio.seek(SeekFrom::Start(0))?;
        blockio.read_exact(&mut buf)?;

        assert_eq!(&buf[..], &['a' as u8, 'b' as u8]);

        Ok(())
    }

    #[test]
    fn short_write_at() -> Result<()> {
        let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());
        let mut ivg = SequentialIvGenerator::new(16);
        let mut crypter = StatefulAes256Ctr::new();

        let mut blockio = BlockIvCryptIo::<
            FromStd<NamedTempFile>,
            Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
            SequentialIvGenerator,
            StatefulAes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            FromStd::new(NamedTempFile::new()?),
            &mut khf,
            &mut ivg,
            &mut crypter,
        );

        blockio.write_all_at(&['a' as u8], 0)?;
        blockio.write_all_at(&['b' as u8], 1)?;

        let mut buf = vec![0; 2];
        blockio.read_exact_at(&mut buf, 0).unwrap();

        assert_eq!(&buf[..], &['a' as u8, 'b' as u8]);

        Ok(())
    }

    #[test]
    fn read_too_much() -> Result<()> {
        let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());
        let mut ivg = SequentialIvGenerator::new(16);
        let mut crypter = StatefulAes256Ctr::new();

        let mut blockio = BlockIvCryptIo::<
            FromStd<NamedTempFile>,
            Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
            SequentialIvGenerator,
            StatefulAes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            FromStd::new(NamedTempFile::new()?),
            &mut khf,
            &mut ivg,
            &mut crypter,
        );

        blockio.write_all(&['a' as u8; 16])?;

        let mut buf = vec![0; BLOCK_SIZE];
        blockio.seek(SeekFrom::Start(0).into())?;
        let n = blockio.read(&mut buf)?;

        assert_eq!(n, 16);
        assert_eq!(&buf[..n], &['a' as u8; 16]);

        Ok(())
    }

    #[test]
    fn read_too_much_at() -> Result<()> {
        let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());
        let mut ivg = SequentialIvGenerator::new(16);
        let mut crypter = StatefulAes256Ctr::new();

        let mut blockio = BlockIvCryptIo::<
            FromStd<NamedTempFile>,
            Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
            SequentialIvGenerator,
            StatefulAes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            FromStd::new(NamedTempFile::new()?),
            &mut khf,
            &mut ivg,
            &mut crypter,
        );

        blockio.write_all_at(&['a' as u8; 16], 0)?;

        let mut buf = vec![0; BLOCK_SIZE];
        let n = blockio.read_at(&mut buf, 0).unwrap();

        assert_eq!(n, 16);
        assert_eq!(&buf[..n], &['a' as u8; 16]);

        Ok(())
    }

    #[test]
    fn random() -> Result<()> {
        for _ in 0..20 {
            let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());
            let mut ivg = SequentialIvGenerator::new(16);
            let mut rng = ThreadRng::default();
            let mut crypter = StatefulAes256Ctr::new();

            let mut blockio = BlockIvCryptIo::<
                FromStd<NamedTempFile>,
                Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
                SequentialIvGenerator,
                StatefulAes256Ctr,
                BLOCK_SIZE,
                KEY_SIZE,
            >::new(
                FromStd::new(NamedTempFile::new()?),
                &mut khf,
                &mut ivg,
                &mut crypter,
            );

            let nbytes = rng.gen::<usize>() % (1 << 16);
            let mut pt = vec![0; nbytes];
            rng.fill_bytes(&mut pt);

            blockio.write_all(&pt)?;

            let mut xt = vec![0; pt.len()];
            blockio.seek(SeekFrom::Start(0).into())?;
            let n = blockio.read(&mut xt)?;

            assert_eq!(n, pt.len());
            assert_eq!(pt, xt);
        }

        Ok(())
    }

    #[test]
    fn random_at() -> Result<()> {
        for _ in 0..20 {
            let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());
            let mut rng = ThreadRng::default();
            let mut ivg = SequentialIvGenerator::new(16);
            let mut crypter = StatefulAes256Ctr::new();

            let mut blockio = BlockIvCryptIo::<
                FromStd<NamedTempFile>,
                Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
                SequentialIvGenerator,
                StatefulAes256Ctr,
                BLOCK_SIZE,
                KEY_SIZE,
            >::new(
                FromStd::new(NamedTempFile::new()?),
                &mut khf,
                &mut ivg,
                &mut crypter,
            );

            let nbytes = rng.gen::<usize>() % (1 << 16);
            let mut pt = vec![0; nbytes];
            rng.fill_bytes(&mut pt);

            blockio.write_all_at(&pt, 0)?;

            let mut xt = vec![0; pt.len()];
            let n = blockio.read_at(&mut xt, 0)?;

            assert_eq!(n, pt.len());
            assert_eq!(pt, xt);
        }

        Ok(())
    }

    #[test]
    fn sequential() -> Result<()> {
        for _ in 0..10 {
            let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());
            let mut rng = ThreadRng::default();
            let mut ivg = SequentialIvGenerator::new(16);
            let mut crypter = StatefulAes256Ctr::new();

            let mut blockio = BlockIvCryptIo::<
                FromStd<NamedTempFile>,
                Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
                SequentialIvGenerator,
                StatefulAes256Ctr,
                BLOCK_SIZE,
                KEY_SIZE,
            >::new(
                FromStd::new(NamedTempFile::new()?),
                &mut khf,
                &mut ivg,
                &mut crypter,
            );

            let mut pt = vec![0; BLOCK_SIZE];
            rng.fill_bytes(&mut pt);

            blockio.write_all(&pt)?;

            blockio.seek(SeekFrom::Start(0).into())?;
            let mut xt = [0];

            for c in &pt {
                let n = blockio.read(&mut xt)?;
                assert_eq!(n, 1);
                assert_eq!(*c, xt[0]);
            }
        }

        Ok(())
    }

    #[test]
    fn sequential_at() -> Result<()> {
        for _ in 0..10 {
            let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());
            let mut rng = ThreadRng::default();
            let mut ivg = SequentialIvGenerator::new(16);
            let mut crypter = StatefulAes256Ctr::new();

            let mut blockio = BlockIvCryptIo::<
                FromStd<NamedTempFile>,
                Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
                SequentialIvGenerator,
                StatefulAes256Ctr,
                BLOCK_SIZE,
                KEY_SIZE,
            >::new(
                FromStd::new(NamedTempFile::new()?),
                &mut khf,
                &mut ivg,
                &mut crypter,
            );

            let mut pt = vec![0; BLOCK_SIZE];
            rng.fill_bytes(&mut pt);

            blockio.write_all_at(&pt, 0)?;

            let mut xt = [0];

            for (i, c) in pt.iter().enumerate() {
                let n = blockio.read_at(&mut xt, i as u64)?;
                assert_eq!(n, 1);
                assert_eq!(*c, xt[0]);
            }
        }

        Ok(())
    }

    #[test]
    fn correctness() -> Result<()> {
        let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());
        let mut ivg = SequentialIvGenerator::new(16);
        let mut crypter = StatefulAes256Ctr::new();

        let mut blockio = BlockIvCryptIo::<
            FromStd<File>,
            Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
            SequentialIvGenerator,
            StatefulAes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            FromStd::new(
                File::options()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open("/tmp/blockivcrypt")?,
            ),
            &mut khf,
            &mut ivg,
            &mut crypter,
        );

        let mut n = 0;
        blockio.seek(SeekFrom::Start(0).into())?;
        n += blockio.write(&['a' as u8; 7])?;
        blockio.seek(SeekFrom::Start(7).into())?;
        n += blockio.write(&['b' as u8; 29])?;
        assert_eq!(n, 36);
        assert_eq!(fs::metadata("/tmp/blockivcrypt")?.len(), 52);

        Ok(())
    }

    #[test]
    fn correctness_at() -> Result<()> {
        let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());
        let mut ivg = SequentialIvGenerator::new(16);
        let mut crypter = StatefulAes256Ctr::new();

        let mut blockio = BlockIvCryptIo::<
            FromStd<File>,
            Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
            SequentialIvGenerator,
            StatefulAes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            FromStd::new(
                File::options()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open("/tmp/blockivcrypt")?,
            ),
            &mut khf,
            &mut ivg,
            &mut crypter,
        );

        let mut n = 0;
        n += blockio.write_at(&['a' as u8; 7], 0)?;
        n += blockio.write_at(&['b' as u8; 29], 7)?;
        assert_eq!(n, 36);
        assert_eq!(fs::metadata("/tmp/blockivcrypt")?.len(), 52);

        Ok(())
    }

    #[test]
    fn short() -> Result<()> {
        let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());
        let mut ivg = SequentialIvGenerator::new(16);
        let mut crypter = StatefulAes256Ctr::new();

        let mut blockio = BlockIvCryptIo::<
            FromStd<File>,
            Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
            SequentialIvGenerator,
            StatefulAes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            FromStd::new(
                File::options()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open("/tmp/blockivcrypt_short")?,
            ),
            &mut khf,
            &mut ivg,
            &mut crypter,
        );

        blockio.seek(SeekFrom::Start(0).into())?;
        let n = blockio.write(&['a' as u8; 24])?;
        blockio.seek(SeekFrom::Start(0).into())?;

        let mut data = vec![0; 400];
        let m = blockio.read(&mut data)?;

        assert_eq!(n, 24);
        assert_eq!(m, 24);
        assert_eq!(&data[..n], &['a' as u8; 24]);
        assert_eq!(
            fs::metadata("/tmp/blockivcrypt_short")?.len(),
            m as u64 + StatefulAes256Ctr::iv_length() as u64
        );

        Ok(())
    }

    #[test]
    fn short_at() -> Result<()> {
        let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());
        let mut ivg = SequentialIvGenerator::new(16);
        let mut crypter = StatefulAes256Ctr::new();

        let mut blockio = BlockIvCryptIo::<
            FromStd<File>,
            Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
            SequentialIvGenerator,
            StatefulAes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            FromStd::new(
                File::options()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open("/tmp/blockivcrypt_short")?,
            ),
            &mut khf,
            &mut ivg,
            &mut crypter,
        );

        let n = blockio.write_at(&['a' as u8; 24], 0)?;

        let mut data = vec![0; 400];
        let m = blockio.read_at(&mut data, 0)?;

        assert_eq!(n, 24);
        assert_eq!(m, 24);
        assert_eq!(&data[..n], &['a' as u8; 24]);
        assert_eq!(
            fs::metadata("/tmp/blockivcrypt_short")?.len(),
            m as u64 + StatefulAes256Ctr::iv_length() as u64
        );

        Ok(())
    }
}
