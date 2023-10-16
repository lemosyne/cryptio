use crate::Key;
use crypter::Crypter;
use embedded_io::{
    blocking::{Read, Seek, Write},
    Io, SeekFrom,
};
use kms::KeyManagementScheme;
use rand::{CryptoRng, RngCore};
use std::marker::PhantomData;

pub enum Block {
    Empty,
    Unaligned {
        iv: Vec<u8>,
        data: Vec<u8>,
        fill: usize,
    },
    Aligned {
        iv: Vec<u8>,
        data: Vec<u8>,
    },
}

pub struct BlockIvCryptIo<'a, IO, KMS, R, C, const BLK_SZ: usize, const KEY_SZ: usize> {
    io: IO,
    kms: &'a mut KMS,
    rng: R,
    pd: PhantomData<C>,
}

impl<'a, IO, KMS, R, C, const BLK_SZ: usize, const KEY_SZ: usize>
    BlockIvCryptIo<'a, IO, KMS, R, C, BLK_SZ, KEY_SZ>
where
    IO: Seek,
    R: RngCore + CryptoRng,
    C: Crypter,
{
    /// Constructs a new `BlockIvCryptoIo`.
    pub fn new(io: IO, kms: &'a mut KMS, rng: R) -> Self {
        Self {
            io,
            kms,
            rng,
            pd: PhantomData,
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

    /// Generates a new IV.
    fn generate_iv(&mut self) -> Vec<u8> {
        let mut iv = vec![0; C::iv_length()];
        self.rng.fill_bytes(&mut iv);
        iv
    }

    /// Extracts out the IV and data from a raw block.
    fn extract_iv_data(&self, mut raw: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        (raw.drain(..C::iv_length()).collect(), raw)
    }

    /// Returns our current offset.
    fn curr_offset(&mut self) -> Result<usize, IO::Error> {
        self.io.stream_position().map(|offset| offset as usize)
    }

    /// Reads a block from a given offset.
    fn read_block(&mut self, offset: usize) -> Result<Block, IO::Error>
    where
        IO: Read,
    {
        let aligned = self.offset_aligned(offset);
        let padding = self.offset_padding(offset);
        let fill = self.offset_fill(offset);

        self.io.seek(SeekFrom::Start(aligned as u64))?;

        let mut raw = vec![0; self.padded_block_size()];
        let nbytes = self.io.read(&mut raw)?;

        // Restore seek cursor if we didn't read anything.
        if nbytes == 0 || nbytes < padding + C::iv_length() {
            self.io.seek(SeekFrom::Start(offset as u64))?;
            return Ok(Block::Empty);
        }

        raw.truncate(nbytes);

        let (iv, data) = self.extract_iv_data(raw);

        if padding == 0 {
            Ok(Block::Aligned { iv, data })
        } else {
            Ok(Block::Unaligned { iv, data, fill })
        }
    }

    /// Writes a block with a prepended IV to a given offset.
    fn write_block(&mut self, offset: usize, iv: &[u8], data: &[u8]) -> Result<usize, IO::Error>
    where
        IO: Read + Write,
    {
        let aligned = self.offset_aligned(offset);
        self.io.seek(SeekFrom::Start(aligned as u64))?;
        self.io.write(&iv)?;
        Ok(self.io.write(&data)?)
    }
}

impl<IO, KMS, R, C, const BLK_SZ: usize, const KEY_SZ: usize> Io
    for BlockIvCryptIo<'_, IO, KMS, R, C, BLK_SZ, KEY_SZ>
where
    IO: Io,
{
    type Error = IO::Error;
}

impl<IO, KMS, R, C, const BLK_SZ: usize, const KEY_SZ: usize> Read
    for BlockIvCryptIo<'_, IO, KMS, R, C, BLK_SZ, KEY_SZ>
where
    IO: Read + Seek,
    KMS: KeyManagementScheme<KeyId = u64, Key = Key<KEY_SZ>>,
    R: RngCore + CryptoRng,
    C: Crypter,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        // Track the bytes we've read and we need to read.
        let mut total = 0;
        let mut size = buf.len();

        // Easier to track where we are in the stream.
        let origin = self.curr_offset()?;
        let mut offset = origin;

        while size > 0 {
            match self.read_block(offset)? {
                Block::Empty => {
                    break;
                }
                Block::Unaligned { iv, data, fill } => {
                    let block = self.offset_block(offset);

                    // Decrypt the bytes we read.
                    let key = self.kms.derive(block as u64).map_err(|_| ()).unwrap();
                    let pt = C::decrypt(&key, &iv, &data).map_err(|_| ()).unwrap();

                    // Calculate the number of bytes we've actually read and copy those bytes in.
                    let nbytes = size.min(pt.len() - fill);
                    if nbytes == 0 {
                        break;
                    }

                    buf[total..total + nbytes].copy_from_slice(&pt[fill..fill + nbytes]);

                    size -= nbytes;
                    offset += nbytes;
                    total += nbytes;
                }
                Block::Aligned { iv, data } => {
                    let block = self.offset_block(offset);

                    // Decrypt the bytes we read.
                    let key = self.kms.derive(block as u64).map_err(|_| ()).unwrap();
                    let pt = C::decrypt(&key, &iv, &data).map_err(|_| ()).unwrap();

                    // Copy in the decrypted bytes.
                    let nbytes = size.min(pt.len());
                    if nbytes == 0 {
                        break;
                    }

                    buf[total..total + nbytes].copy_from_slice(&pt[..nbytes]);

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

impl<IO, KMS, R, C, const BLK_SZ: usize, const KEY_SZ: usize> Write
    for BlockIvCryptIo<'_, IO, KMS, R, C, BLK_SZ, KEY_SZ>
where
    IO: Read + Write + Seek,
    KMS: KeyManagementScheme<KeyId = u64, Key = Key<KEY_SZ>>,
    R: RngCore + CryptoRng,
    C: Crypter,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        // Track the bytes we've written and we need to write.
        let mut total = 0;
        let mut size = buf.len();

        let origin = self.curr_offset()?;
        let mut offset = origin;

        // If we aren't block-aligned, then we need to rewrite the bytes preceding our current
        // offset in the block.
        if !self.offset_is_aligned(offset) {
            match self.read_block(offset)? {
                // There should be something there, but we didn't read anything.
                Block::Empty => {
                    self.io.seek(SeekFrom::Start(origin as u64))?;
                    return Ok(total);
                }
                Block::Unaligned { iv, data, fill } => {
                    let block = self.offset_block(offset);

                    // Decrypt the bytes we read.
                    let key = self.kms.derive(block as u64).map_err(|_| ()).unwrap();
                    let mut pt = C::decrypt(&key, &iv, &data).map_err(|_| ()).unwrap();

                    // Extending the plaintext to a full block covers the case when what we are
                    // overwriting with is longer than what is currently in the block. If we don't
                    // do this, the `.copy_from_slice()` won't work.
                    pt.extend(vec![0; BLK_SZ - pt.len()]);

                    // Calculate the number of bytes we've actually read and update the bytes we're
                    // trying to overwrite in the plaintext.
                    let rest = size.min(pt.len() - fill);
                    pt[fill..fill + rest].copy_from_slice(&buf[..rest]);

                    // Re-encrypt the plaintext.
                    let iv = self.generate_iv();
                    let key = self.kms.update(block as u64).map_err(|_| ()).unwrap();
                    let ct = C::encrypt(&key, &iv, &pt).map_err(|_| ()).unwrap();

                    // Write the IV and ciphertext.
                    let amount = pt.len().max(fill + rest);
                    let nbytes = self.write_block(offset, &iv, &ct[..amount])?;
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
        }

        // We write full blocks of data as long as we're block-aligned.
        while size > 0 && size / BLK_SZ > 0 && self.offset_is_aligned(offset) {
            let block = self.offset_block(offset);

            // Encrypt the data.
            let iv = self.generate_iv();
            let key = self.kms.update(block as u64).map_err(|_| ()).unwrap();
            let ct = C::encrypt(&key, &iv, &buf[total..total + BLK_SZ])
                .map_err(|_| ())
                .unwrap();

            // Write the IV and ciphertext.
            let nbytes = self.write_block(offset, &iv, &ct)?;
            if nbytes == 0 {
                self.io.seek(SeekFrom::Start((origin + total) as u64))?;
                return Ok(total);
            }

            total += nbytes;
            offset += nbytes;
            size -= nbytes;
        }

        // We have remaining bytes that don't fill an entire block.
        if size > 0 {
            match self.read_block(offset)? {
                // Receiving block empty means that there aren't any trailing bytes that we need to
                // rewrite, so we can just go ahead and write out the remaining bytes.
                Block::Empty => {
                    let block = self.offset_block(offset);

                    // Encrypt the remaining bytes.
                    let iv = self.generate_iv();
                    let key = self.kms.update(block as u64).map_err(|_| ()).unwrap();
                    let ct = C::encrypt(&key, &iv, &buf[total..total + size])
                        .map_err(|_| ())
                        .unwrap();

                    // Write the block.
                    total += self.write_block(offset, &iv, &ct)?;
                }
                // We need to rewrite any bytes trailing the overwritten bytes.
                Block::Aligned { iv, data } => {
                    let block = self.offset_block(offset);

                    // Decrypt the bytes.
                    let key = self.kms.derive(block as u64).map_err(|_| ()).unwrap();
                    let mut pt = C::decrypt(&key, &iv, &data).map_err(|_| ()).unwrap();

                    // Copy in the bytes that we want to update.
                    pt[..size].copy_from_slice(&buf[total..total + size]);

                    // Encrypt the plaintext.
                    let iv = self.generate_iv();
                    let key = self.kms.update(block as u64).map_err(|_| ()).unwrap();
                    let ct = C::encrypt(&key, &iv, &pt).map_err(|_| ()).unwrap();

                    // Write the block.
                    let nbytes = size.max(pt.len());
                    self.write_block(offset, &iv, &ct[..nbytes])?;

                    total += size.min(nbytes);
                }
                _ => {
                    panic!("shouldn't be performing an unaligned write");
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
    use anyhow::Result;
    use crypter::openssl::Aes256Ctr;
    use embedded_io::{
        adapters::FromStd,
        blocking::{Read, Seek, Write},
        SeekFrom,
    };
    use hasher::openssl::{Sha3_256, SHA3_256_MD_SIZE};
    use khf::Khf;
    use rand::rngs::ThreadRng;
    use tempfile::NamedTempFile;

    const BLOCK_SIZE: usize = 128;
    const KEY_SIZE: usize = SHA3_256_MD_SIZE;

    #[test]
    fn simple() -> Result<()> {
        let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());

        let mut blockio = BlockIvCryptIo::<
            FromStd<NamedTempFile>,
            Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
            ThreadRng,
            Aes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            FromStd::new(NamedTempFile::new()?),
            &mut khf,
            ThreadRng::default(),
        );

        blockio.write_all(&['a' as u8; BLOCK_SIZE])?;

        let mut buf = vec![0; BLOCK_SIZE];
        blockio.seek(SeekFrom::Start(0))?;
        blockio.read_exact(&mut buf)?;

        assert_eq!(&buf[..], &['a' as u8; BLOCK_SIZE]);

        Ok(())
    }

    // Writes 4 blocks of 'a's, then 4 'b's at offset 3.
    #[test]
    fn offset_write() -> Result<()> {
        let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());

        let mut blockio = BlockIvCryptIo::<
            FromStd<NamedTempFile>,
            Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
            ThreadRng,
            Aes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            FromStd::new(NamedTempFile::new()?),
            &mut khf,
            ThreadRng::default(),
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

    // Writes 2 blocks of 'a's and a block of 'b' right in the middle.
    #[test]
    fn misaligned_write() -> Result<()> {
        let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());

        let mut blockio = BlockIvCryptIo::<
            FromStd<NamedTempFile>,
            Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
            ThreadRng,
            Aes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            FromStd::new(NamedTempFile::new()?),
            &mut khf,
            ThreadRng::default(),
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

    #[test]
    fn short_write() -> Result<()> {
        let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());

        let mut blockio = BlockIvCryptIo::<
            FromStd<NamedTempFile>,
            Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
            ThreadRng,
            Aes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            FromStd::new(NamedTempFile::new()?),
            &mut khf,
            ThreadRng::default(),
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
    fn read_too_much() -> Result<()> {
        let mut khf = Khf::new(&[4, 4, 4, 4], ThreadRng::default());

        let mut blockio = BlockIvCryptIo::<
            FromStd<NamedTempFile>,
            Khf<ThreadRng, Sha3_256, SHA3_256_MD_SIZE>,
            ThreadRng,
            Aes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            FromStd::new(NamedTempFile::new()?),
            &mut khf,
            ThreadRng::default(),
        );

        blockio.write_all(&['a' as u8; 16])?;

        let mut buf = vec![0; BLOCK_SIZE];
        blockio.seek(SeekFrom::Start(0).into())?;
        let n = blockio.read(&mut buf)?;

        assert_eq!(n, 16);
        assert_eq!(&buf[..n], &['a' as u8; 16]);

        Ok(())
    }
}
