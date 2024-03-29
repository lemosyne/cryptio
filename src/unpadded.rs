use crate::Key;
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

pub struct UnpaddedBlockIvCryptIo<'a, IO, KMS, C, const BLK_SZ: usize, const KEY_SZ: usize> {
    io: IO,
    kms: &'a mut KMS,
    crypter: &'a mut C,
}

impl<'a, IO, KMS, C, const BLK_SZ: usize, const KEY_SZ: usize>
    UnpaddedBlockIvCryptIo<'a, IO, KMS, C, BLK_SZ, KEY_SZ>
where
    IO: Io,
    C: StatefulCrypter,
{
    /// Constructs a new `BlockIvCryptoIo`.
    pub fn new(io: IO, kms: &'a mut KMS, crypter: &'a mut C) -> Self
    where
        C: Default,
    {
        Self { io, kms, crypter }
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
        BLK_SZ + 0
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
        if nbytes == 0 || nbytes < padding + 0 {
            self.io.seek(SeekFrom::Start(offset as u64))?;
            return Ok(Block::Empty);
        }

        // The real data size (doesn't include IV).
        let real = nbytes - 0;

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
        if nbytes == 0 || nbytes < padding + 0 {
            return Ok(Block::Empty);
        }

        // The real data size (doesn't include IV).
        let real = nbytes - 0;

        if padding == 0 {
            Ok(Block::Aligned { real })
        } else {
            Ok(Block::Unaligned { real, fill })
        }
    }

    /// Writes a block with a prepended IV to a given offset.
    fn write_block(&mut self, offset: usize, data: &[u8]) -> Result<usize, IO::Error>
    where
        IO: Write + Seek,
    {
        let aligned = self.offset_aligned(offset);
        self.io.seek(SeekFrom::Start(aligned as u64))?;
        // self.io.write(&iv)?;
        let n = self.io.write(&data)?;
        self.io.flush()?;
        Ok(n)
    }

    /// Writes a block with a prepended IV to a given offset.
    fn write_block_at(&mut self, offset: usize, data: &[u8]) -> Result<usize, IO::Error>
    where
        IO: WriteAt + Write,
    {
        let aligned = self.offset_aligned(offset);
        // self.io.write_at(iv, aligned as u64)?;
        let n = self.io.write_at(data, (aligned + 0) as u64)?;
        self.io.flush()?;
        Ok(n)
    }
}

impl<IO, KMS, C, const BLK_SZ: usize, const KEY_SZ: usize> Io
    for UnpaddedBlockIvCryptIo<'_, IO, KMS, C, BLK_SZ, KEY_SZ>
where
    IO: Io,
{
    type Error = IO::Error;
}

impl<IO, KMS, C, const BLK_SZ: usize, const KEY_SZ: usize> Read
    for UnpaddedBlockIvCryptIo<'_, IO, KMS, C, BLK_SZ, KEY_SZ>
where
    IO: Read + Seek,
    KMS: KeyManagementScheme<KeyId = u64, Key = Key<KEY_SZ>>,
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
                    let (_iv, data) = scratch.split_at_mut(0);
                    let iv = &vec![0; C::iv_length()];

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
                    let (_iv, data) = scratch.split_at_mut(0);
                    let iv = &vec![0; C::iv_length()];

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

        self.io.seek(SeekFrom::Start(offset as u64))?;

        Ok(total)
    }
}

impl<IO, KMS, C, const BLK_SZ: usize, const KEY_SZ: usize> ReadAt
    for UnpaddedBlockIvCryptIo<'_, IO, KMS, C, BLK_SZ, KEY_SZ>
where
    IO: ReadAt,
    KMS: KeyManagementScheme<KeyId = u64, Key = Key<KEY_SZ>>,
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
                    let (_iv, data) = scratch.split_at_mut(0);
                    let iv = &vec![0; C::iv_length()];

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
                    let (_iv, data) = scratch.split_at_mut(0);
                    let iv = &vec![0; C::iv_length()];

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

impl<IO, KMS, C, const BLK_SZ: usize, const KEY_SZ: usize> Write
    for UnpaddedBlockIvCryptIo<'_, IO, KMS, C, BLK_SZ, KEY_SZ>
where
    IO: Read + Write + Seek,
    KMS: KeyManagementScheme<KeyId = u64, Key = Key<KEY_SZ>>,
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
                        self.io.seek(SeekFrom::Start(offset as u64))?;
                        return Ok(total);
                    }
                    Block::Unaligned { real, fill } => {
                        let block = self.offset_block(offset);
                        let (_iv, data) = scratch.split_at_mut(0);
                        let iv = &vec![0; C::iv_length()];

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
                        // self.ivgen.generate_iv(iv).map_err(|_| ()).unwrap();
                        let key = self.kms.update(block as u64).map_err(|_| ()).unwrap();
                        self.crypter
                            .encrypt(&key, iv, data)
                            .map_err(|_| ())
                            .unwrap();

                        // Write the IV and ciphertext.
                        // The amount of bytes could exceed what was there originally (real).
                        let amount = real.max(fill + rest);
                        let nbytes = self.write_block(offset, &data[..amount])?;
                        let written = rest.min(nbytes - fill);
                        if nbytes == 0 || written == 0 {
                            self.io.seek(SeekFrom::Start(offset as u64))?;
                            return Ok(total);
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
                let (_iv, _data) = scratch.split_at_mut(0);
                let iv = &vec![0; C::iv_length()];

                // Copy data to a scratch block buffer for encryption.
                scratch_block.copy_from_slice(&buf[total..total + BLK_SZ]);

                // Encrypt the data with a new IV.
                // self.ivgen.generate_iv(iv).map_err(|_| ()).unwrap();
                let key = self.kms.update(block as u64).map_err(|_| ()).unwrap();
                self.crypter
                    .encrypt(&key, &iv, &mut scratch_block)
                    .map_err(|_| ())
                    .unwrap();

                // Write the IV and ciphertext.
                let nbytes = self.write_block(offset, &scratch_block)?;
                if nbytes == 0 {
                    self.io.seek(SeekFrom::Start(offset as u64))?;
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
                        let (_iv, _data) = scratch.split_at_mut(0);
                        let iv = &vec![0; C::iv_length()];

                        // Copy over the bytes to the scratch buffer for encryption.
                        scratch_block[..size].copy_from_slice(&buf[total..total + size]);

                        // Encrypt the remaining bytes.
                        // self.ivgen.generate_iv(iv).map_err(|_| ()).unwrap();
                        let key = self.kms.update(block as u64).map_err(|_| ()).unwrap();

                        self.crypter
                            .encrypt(&key, iv, &mut scratch_block[..size])
                            .map_err(|_| ())
                            .unwrap();

                        // Write the block.
                        let nbytes = self.write_block(offset, &scratch_block[..size])?;

                        total += nbytes;
                        offset += nbytes;
                        size -= nbytes;
                    }
                    // We need to rewrite any bytes trailing the overwritten bytes.
                    Block::Aligned { real } => {
                        let block = self.offset_block(offset);
                        let (_iv, data) = scratch.split_at_mut(0);
                        let iv = &vec![0; C::iv_length()];

                        // Decrypt the bytes.
                        let key = self.kms.derive(block as u64).map_err(|_| ()).unwrap();

                        self.crypter
                            .decrypt(&key, iv, data)
                            .map_err(|_| ())
                            .unwrap();

                        // Copy in the bytes that we want to update.
                        data[..size].copy_from_slice(&buf[total..total + size]);

                        // Encrypt the plaintext.
                        // self.ivgen.generate_iv(iv).map_err(|_| ()).unwrap();
                        let key = self.kms.update(block as u64).map_err(|_| ()).unwrap();

                        self.crypter
                            .encrypt(&key, iv, data)
                            .map_err(|_| ())
                            .unwrap();

                        // Write the block.
                        let nbytes = size.max(real);
                        self.write_block(offset, &data[..nbytes])?;

                        total += size.min(nbytes);
                        offset += size.min(nbytes);
                        size -= size.min(nbytes);
                    }
                    _ => {
                        panic!("shouldn't be performing an unaligned write");
                    }
                }
            }
        }

        self.io.seek(SeekFrom::Start(offset as u64))?;

        Ok(total)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.io.flush()
    }
}

impl<IO, KMS, C, const BLK_SZ: usize, const KEY_SZ: usize> WriteAt
    for UnpaddedBlockIvCryptIo<'_, IO, KMS, C, BLK_SZ, KEY_SZ>
where
    IO: ReadAt + WriteAt + Write,
    KMS: KeyManagementScheme<KeyId = u64, Key = Key<KEY_SZ>>,
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
                        let (_iv, data) = scratch.split_at_mut(0);
                        let iv = &vec![0; C::iv_length()];

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
                        // self.ivgen.generate_iv(iv).map_err(|_| ()).unwrap();
                        let key = self.kms.update(block as u64).map_err(|_| ()).unwrap();
                        self.crypter
                            .encrypt(&key, iv, data)
                            .map_err(|_| ())
                            .unwrap();

                        // Write the IV and ciphertext.
                        // The amount of bytes could exceed what was there originally (real).
                        let amount = real.max(fill + rest);
                        let nbytes = self.write_block_at(offset, &data[..amount])?;
                        let written = rest.min(nbytes - fill);
                        if nbytes == 0 || written == 0 {
                            return Ok(total);
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
                let (_iv, _data) = scratch.split_at_mut(0);
                let iv = &vec![0; C::iv_length()];

                // Copy data to a scratch block buffer for encryption.
                scratch_block.copy_from_slice(&buf[total..total + BLK_SZ]);

                // Encrypt the data with a new IV.
                // self.ivgen.generate_iv(iv).map_err(|_| ()).unwrap();
                let key = self.kms.update(block as u64).map_err(|_| ()).unwrap();
                self.crypter
                    .encrypt(&key, &iv, &mut scratch_block)
                    .map_err(|_| ())
                    .unwrap();

                // Write the IV and ciphertext.
                let nbytes = self.write_block_at(offset, &scratch_block)?;
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
                        let (_iv, _data) = scratch.split_at_mut(0);
                        let iv = &vec![0; C::iv_length()];

                        // Copy over the bytes to the scratch buffer for encryption.
                        scratch_block[..size].copy_from_slice(&buf[total..total + size]);

                        // Encrypt the remaining bytes.
                        // self.ivgen.generate_iv(iv).map_err(|_| ()).unwrap();
                        let key = self.kms.update(block as u64).map_err(|_| ()).unwrap();

                        self.crypter
                            .encrypt(&key, iv, &mut scratch_block[..size])
                            .map_err(|_| ())
                            .unwrap();

                        // Write the block.
                        let nbytes = self.write_block_at(offset, &scratch_block[..size])?;

                        total += nbytes;
                        offset += nbytes;
                        size -= nbytes;
                    }
                    // We need to rewrite any bytes trailing the overwritten bytes.
                    Block::Aligned { real } => {
                        let block = self.offset_block(offset);
                        let (_iv, data) = scratch.split_at_mut(0);
                        let iv = &vec![0; C::iv_length()];

                        // Decrypt the bytes.
                        let key = self.kms.derive(block as u64).map_err(|_| ()).unwrap();

                        self.crypter
                            .decrypt(&key, iv, data)
                            .map_err(|_| ())
                            .unwrap();

                        // Copy in the bytes that we want to update.
                        data[..size].copy_from_slice(&buf[total..total + size]);

                        // Encrypt the plaintext.
                        // self.ivgen.generate_iv(iv).map_err(|_| ()).unwrap();
                        let key = self.kms.update(block as u64).map_err(|_| ()).unwrap();

                        self.crypter
                            .encrypt(&key, iv, data)
                            .map_err(|_| ())
                            .unwrap();

                        // Write the block.
                        let nbytes = size.max(real);
                        self.write_block_at(offset, &data[..nbytes])?;

                        total += size.min(nbytes);
                        offset += size.min(nbytes);
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

impl<IO, KMS, C, const BLK_SZ: usize, const KEY_SZ: usize> Seek
    for UnpaddedBlockIvCryptIo<'_, IO, KMS, C, BLK_SZ, KEY_SZ>
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
    use anyhow::Result;
    use crypter::aes::Aes256Ctr;
    use embedded_io::{adapters::FromStd, SeekFrom};
    use hasher::sha3::{Sha3_256, SHA3_256_MD_SIZE};
    use khf::Khf;
    use rand::{rngs::ThreadRng, Rng, RngCore};
    use std::fs::{self, File};
    use tempfile::NamedTempFile;

    const BLOCK_SIZE: usize = 128;
    const KEY_SIZE: usize = SHA3_256_MD_SIZE;

    #[test]
    fn simple() -> Result<()> {
        let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());
        let mut crypter = Aes256Ctr::new();

        let mut blockio =
            UnpaddedBlockIvCryptIo::<
                FromStd<NamedTempFile>,
                Khf<Sha3_256, SHA3_256_MD_SIZE>,
                Aes256Ctr,
                BLOCK_SIZE,
                KEY_SIZE,
            >::new(FromStd::new(NamedTempFile::new()?), &mut khf, &mut crypter);

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
        let mut crypter = Aes256Ctr::new();

        let mut blockio =
            UnpaddedBlockIvCryptIo::<
                FromStd<NamedTempFile>,
                Khf<Sha3_256, SHA3_256_MD_SIZE>,
                Aes256Ctr,
                BLOCK_SIZE,
                KEY_SIZE,
            >::new(FromStd::new(NamedTempFile::new()?), &mut khf, &mut crypter);

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
        let mut crypter = Aes256Ctr::new();

        let mut blockio =
            UnpaddedBlockIvCryptIo::<
                FromStd<NamedTempFile>,
                Khf<Sha3_256, SHA3_256_MD_SIZE>,
                Aes256Ctr,
                BLOCK_SIZE,
                KEY_SIZE,
            >::new(FromStd::new(NamedTempFile::new()?), &mut khf, &mut crypter);

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
        let mut crypter = Aes256Ctr::new();

        let mut blockio =
            UnpaddedBlockIvCryptIo::<
                FromStd<NamedTempFile>,
                Khf<Sha3_256, SHA3_256_MD_SIZE>,
                Aes256Ctr,
                BLOCK_SIZE,
                KEY_SIZE,
            >::new(FromStd::new(NamedTempFile::new()?), &mut khf, &mut crypter);

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
        let mut crypter = Aes256Ctr::new();

        let mut blockio =
            UnpaddedBlockIvCryptIo::<
                FromStd<NamedTempFile>,
                Khf<Sha3_256, SHA3_256_MD_SIZE>,
                Aes256Ctr,
                BLOCK_SIZE,
                KEY_SIZE,
            >::new(FromStd::new(NamedTempFile::new()?), &mut khf, &mut crypter);

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
        let mut crypter = Aes256Ctr::new();

        let mut blockio =
            UnpaddedBlockIvCryptIo::<
                FromStd<NamedTempFile>,
                Khf<Sha3_256, SHA3_256_MD_SIZE>,
                Aes256Ctr,
                BLOCK_SIZE,
                KEY_SIZE,
            >::new(FromStd::new(NamedTempFile::new()?), &mut khf, &mut crypter);

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
        let mut crypter = Aes256Ctr::new();

        let mut blockio =
            UnpaddedBlockIvCryptIo::<
                FromStd<NamedTempFile>,
                Khf<Sha3_256, SHA3_256_MD_SIZE>,
                Aes256Ctr,
                BLOCK_SIZE,
                KEY_SIZE,
            >::new(FromStd::new(NamedTempFile::new()?), &mut khf, &mut crypter);

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
        let mut crypter = Aes256Ctr::new();

        let mut blockio =
            UnpaddedBlockIvCryptIo::<
                FromStd<NamedTempFile>,
                Khf<Sha3_256, SHA3_256_MD_SIZE>,
                Aes256Ctr,
                BLOCK_SIZE,
                KEY_SIZE,
            >::new(FromStd::new(NamedTempFile::new()?), &mut khf, &mut crypter);

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
        let mut crypter = Aes256Ctr::new();

        let mut blockio =
            UnpaddedBlockIvCryptIo::<
                FromStd<NamedTempFile>,
                Khf<Sha3_256, SHA3_256_MD_SIZE>,
                Aes256Ctr,
                BLOCK_SIZE,
                KEY_SIZE,
            >::new(FromStd::new(NamedTempFile::new()?), &mut khf, &mut crypter);

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
        let mut crypter = Aes256Ctr::new();

        let mut blockio =
            UnpaddedBlockIvCryptIo::<
                FromStd<NamedTempFile>,
                Khf<Sha3_256, SHA3_256_MD_SIZE>,
                Aes256Ctr,
                BLOCK_SIZE,
                KEY_SIZE,
            >::new(FromStd::new(NamedTempFile::new()?), &mut khf, &mut crypter);

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
            let mut rng = ThreadRng::default();
            let mut crypter = Aes256Ctr::new();

            let mut blockio =
                UnpaddedBlockIvCryptIo::<
                    FromStd<NamedTempFile>,
                    Khf<Sha3_256, SHA3_256_MD_SIZE>,
                    Aes256Ctr,
                    BLOCK_SIZE,
                    KEY_SIZE,
                >::new(FromStd::new(NamedTempFile::new()?), &mut khf, &mut crypter);

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
            let mut crypter = Aes256Ctr::new();

            let mut blockio =
                UnpaddedBlockIvCryptIo::<
                    FromStd<NamedTempFile>,
                    Khf<Sha3_256, SHA3_256_MD_SIZE>,
                    Aes256Ctr,
                    BLOCK_SIZE,
                    KEY_SIZE,
                >::new(FromStd::new(NamedTempFile::new()?), &mut khf, &mut crypter);

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
            let mut crypter = Aes256Ctr::new();

            let mut blockio =
                UnpaddedBlockIvCryptIo::<
                    FromStd<NamedTempFile>,
                    Khf<Sha3_256, SHA3_256_MD_SIZE>,
                    Aes256Ctr,
                    BLOCK_SIZE,
                    KEY_SIZE,
                >::new(FromStd::new(NamedTempFile::new()?), &mut khf, &mut crypter);

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
            let mut crypter = Aes256Ctr::new();

            let mut blockio =
                UnpaddedBlockIvCryptIo::<
                    FromStd<NamedTempFile>,
                    Khf<Sha3_256, SHA3_256_MD_SIZE>,
                    Aes256Ctr,
                    BLOCK_SIZE,
                    KEY_SIZE,
                >::new(FromStd::new(NamedTempFile::new()?), &mut khf, &mut crypter);

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
        let mut crypter = Aes256Ctr::new();

        let mut blockio = UnpaddedBlockIvCryptIo::<
            FromStd<File>,
            Khf<Sha3_256, SHA3_256_MD_SIZE>,
            Aes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            FromStd::new(
                File::options()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open("/tmp/unpaddedblockivcrypt")?,
            ),
            &mut khf,
            &mut crypter,
        );

        let mut n = 0;
        blockio.seek(SeekFrom::Start(0).into())?;
        n += blockio.write(&['a' as u8; 7])?;
        blockio.seek(SeekFrom::Start(7).into())?;
        n += blockio.write(&['b' as u8; 29])?;

        let mut buf = vec![0; 36];
        blockio.seek(SeekFrom::Start(0).into())?;
        blockio.read(&mut buf[0..7]).unwrap();
        blockio.read(&mut buf[7..36]).unwrap();

        assert_eq!(n, 36);
        assert_eq!(fs::metadata("/tmp/unpaddedblockivcrypt")?.len(), 36);
        assert_eq!(&buf[0..7], &['a' as u8; 7]);
        assert_eq!(&buf[7..36], &['b' as u8; 29]);

        Ok(())
    }

    #[test]
    fn correctness_at() -> Result<()> {
        let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());
        let mut crypter = Aes256Ctr::new();

        let mut blockio = UnpaddedBlockIvCryptIo::<
            FromStd<File>,
            Khf<Sha3_256, SHA3_256_MD_SIZE>,
            Aes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            FromStd::new(
                File::options()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open("/tmp/unpaddedblockivcrypt_at")?,
            ),
            &mut khf,
            &mut crypter,
        );

        let mut n = 0;
        n += blockio.write_at(&['a' as u8; 7], 0)?;
        n += blockio.write_at(&['b' as u8; 29], 7)?;

        let mut buf = vec![0; 36];
        blockio.read_at(&mut buf[0..7], 0).unwrap();
        blockio.read_at(&mut buf[7..36], 7).unwrap();

        assert_eq!(n, 36);
        assert_eq!(fs::metadata("/tmp/unpaddedblockivcrypt_at")?.len(), 36);
        assert_eq!(&buf[0..7], &['a' as u8; 7]);
        assert_eq!(&buf[7..36], &['b' as u8; 29]);

        Ok(())
    }

    #[test]
    fn short() -> Result<()> {
        let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());
        let mut crypter = Aes256Ctr::new();

        let mut blockio = UnpaddedBlockIvCryptIo::<
            FromStd<File>,
            Khf<Sha3_256, SHA3_256_MD_SIZE>,
            Aes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            FromStd::new(
                File::options()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open("/tmp/unpaddedblockivcrypt_short")?,
            ),
            &mut khf,
            &mut crypter,
        );

        let stuff = ['a' as u8; 24];
        blockio.seek(SeekFrom::Start(0).into())?;
        let n = blockio.write(&stuff)?;
        blockio.seek(SeekFrom::Start(0).into())?;

        let mut data = vec![0; 400];
        let m = blockio.read(&mut data)?;

        assert_eq!(n, 24);
        assert_eq!(m, 24);
        assert_eq!(&data[..n], &stuff);

        Ok(())
    }

    #[test]
    fn short_at() -> Result<()> {
        let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());
        let mut crypter = Aes256Ctr::new();

        let mut blockio = UnpaddedBlockIvCryptIo::<
            FromStd<File>,
            Khf<Sha3_256, SHA3_256_MD_SIZE>,
            Aes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            FromStd::new(
                File::options()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open("/tmp/unpaddedblockivcrypt_short_at")?,
            ),
            &mut khf,
            &mut crypter,
        );

        let n = blockio.write_at(&['a' as u8; 24], 0)?;

        let mut data = vec![0; 400];
        let m = blockio.read_at(&mut data, 0)?;

        assert_eq!(n, 24);
        assert_eq!(m, 24);
        assert_eq!(&data[..n], &['a' as u8; 24]);

        Ok(())
    }
}
