use crate::Key;
use crypter::{Crypter, StatefulCrypter};
use minimal_io::{
    blocking::{Read, Write},
    Io, Seek, SeekFrom,
};
use std::marker::PhantomData;

pub struct CryptIo<IO, C, const BLK_SZ: usize, const KEY_SZ: usize> {
    io: IO,
    key: Key<KEY_SZ>,
    pd: PhantomData<C>,
}

impl<IO, C, const BLK_SZ: usize, const KEY_SZ: usize> CryptIo<IO, C, BLK_SZ, KEY_SZ> {
    pub fn new(io: IO, key: Key<KEY_SZ>) -> Self {
        Self {
            io,
            key,
            pd: PhantomData,
        }
    }
}

impl<IO, C, const BLK_SZ: usize, const KEY_SZ: usize> Io for CryptIo<IO, C, BLK_SZ, KEY_SZ>
where
    IO: Io,
{
    type Error = IO::Error;
}

impl<IO, C, const BLK_SZ: usize, const KEY_SZ: usize> Read for CryptIo<IO, C, BLK_SZ, KEY_SZ>
where
    IO: Read + Seek,
    C: Crypter,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let mut total = 0;
        let mut size = buf.len();

        let origin = self.io.stream_position()?;
        let mut offset = origin as usize;

        // The offset may be within a block. This requires the bytes before the offset in the block
        // and the bytes after the offset to be read.
        if offset % BLK_SZ != 0 {
            let block = offset / BLK_SZ;
            let fill = offset % BLK_SZ;
            let rest = size.min(BLK_SZ - fill);

            let mut tmp_buf = vec![0; (fill + rest) as usize];
            let off = block * BLK_SZ;

            self.io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = self.io.read(&mut tmp_buf)?;
            let actually_read = nbytes - fill;
            if nbytes == 0 || actually_read == 0 {
                self.io.seek(SeekFrom::Start(origin))?;
                return Ok(0);
            }

            C::onetime_decrypt(&self.key, &mut tmp_buf)
                .map_err(|_| ())
                .unwrap();

            buf[..actually_read].copy_from_slice(&tmp_buf[fill..fill + actually_read]);

            offset += actually_read;
            total += actually_read;
            size -= actually_read;
        }

        // At this point, the offset we want to read from is block-aligned. If it isn't, then we
        // must have read all the bytes. Otherwise, read in the rest of the bytes block-by-block.
        while size > 0 && offset % BLK_SZ == 0 {
            let block = offset / BLK_SZ;
            let rest = size.min(BLK_SZ);

            let mut tmp_buf = vec![0; rest];
            let off = block * BLK_SZ;

            self.io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = self.io.read(&mut tmp_buf)?;
            if nbytes == 0 {
                self.io.seek(SeekFrom::Start(origin + total as u64))?;
                return Ok(total);
            }

            C::onetime_decrypt(&self.key, &mut tmp_buf)
                .map_err(|_| ())
                .unwrap();

            buf[total..total + nbytes].copy_from_slice(&tmp_buf[..nbytes]);

            offset += nbytes;
            size -= nbytes;
            total += nbytes;
        }

        self.io.seek(SeekFrom::Start(origin + total as u64))?;

        Ok(total)
    }
}

impl<IO, C, const BLK_SZ: usize, const KEY_SZ: usize> Write for CryptIo<IO, C, BLK_SZ, KEY_SZ>
where
    IO: Read + Write + Seek,
    C: Crypter,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let mut total = 0;
        let mut size = buf.len();

        let origin = self.io.stream_position()?;
        let mut offset = origin as usize;

        // The write offset may or may not be block-aligned. If it isn't, then the bytes in the
        // block preceding the offset byte should be read as well. The number of bytes to write
        // starting from the offset should be the minimum of the total bytes left to write and the
        // rest of the bytes in the block.
        if offset % BLK_SZ != 0 {
            let block = offset / BLK_SZ;
            let fill = offset % BLK_SZ;
            let rest = size.min(BLK_SZ - fill);

            let mut tmp_buf = vec![0; BLK_SZ];
            let off = block * BLK_SZ;

            self.io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = self.io.read(&mut tmp_buf)?;
            if nbytes == 0 {
                self.io.seek(SeekFrom::Start(origin))?;
                return Ok(0);
            }

            C::onetime_decrypt(&self.key, &mut tmp_buf)
                .map_err(|_| ())
                .unwrap();

            tmp_buf[fill..fill + rest].copy_from_slice(&buf[..rest]);

            C::onetime_encrypt(&self.key, &mut tmp_buf)
                .map_err(|_| ())
                .unwrap();

            let amount = nbytes.max(fill + rest);
            self.io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = self.io.write(&tmp_buf[..amount])?;
            let actually_written = rest.min(nbytes - fill);
            if nbytes == 0 || actually_written == 0 {
                self.io.seek(SeekFrom::Start(origin))?;
                return Ok(0);
            }

            offset += actually_written;
            size -= actually_written;
            total += actually_written;
        }

        // The offset we want to write to should be block-aligned at this point. If not, then we
        // must have written out all the bytes already. Otherwise, write the rest of the bytes
        // block-by-block.
        while size > 0 && size / BLK_SZ > 0 && offset % BLK_SZ == 0 {
            let block = offset / BLK_SZ;

            let mut tmp_buf = buf[total..total + BLK_SZ].to_vec();
            C::onetime_encrypt(&self.key, &mut tmp_buf)
                .map_err(|_| ())
                .unwrap();

            let off = block * BLK_SZ;
            self.io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = self.io.write(&tmp_buf)?;
            if nbytes == 0 {
                self.io.seek(SeekFrom::Start(origin + total as u64))?;
                return Ok(total);
            }

            offset += nbytes;
            size -= nbytes;
            total += nbytes;
        }

        // Write any remaining bytes that don't fill an entire block. We handle this specially
        // since we have to read in the block to decrypt the bytes after the overwritten bytes.
        if size > 0 {
            let block = offset / BLK_SZ;

            // Try to read a whole block.
            let mut tmp_buf = vec![0; BLK_SZ];
            let off = block * BLK_SZ;
            self.io.seek(SeekFrom::Start(off as u64))?;
            let actually_read = self.io.read(&mut tmp_buf)?;
            let actually_write = size.max(actually_read);

            C::onetime_decrypt(&self.key, &mut tmp_buf)
                .map_err(|_| ())
                .unwrap();

            tmp_buf[..size].copy_from_slice(&buf[total..total + size]);

            C::onetime_encrypt(&self.key, &mut tmp_buf)
                .map_err(|_| ())
                .unwrap();

            self.io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = self.io.write(&tmp_buf[..actually_write])?;
            total += size.min(nbytes as usize);

            if nbytes == 0 {
                self.io.seek(SeekFrom::Start(origin + total as u64))?;
                return Ok(total);
            }
        }

        self.io.seek(SeekFrom::Start(origin + total as u64))?;

        Ok(total)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.io.flush()
    }
}

impl<IO, C, const BLK_SZ: usize, const KEY_SZ: usize> Seek for CryptIo<IO, C, BLK_SZ, KEY_SZ>
where
    IO: Seek,
{
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, Self::Error> {
        self.io.seek(pos)
    }
}

pub struct StatefulCryptIo<'a, IO, C, const BLK_SZ: usize, const KEY_SZ: usize> {
    io: IO,
    key: Key<KEY_SZ>,
    crypter: &'a mut C,
}

impl<'a, IO, C, const BLK_SZ: usize, const KEY_SZ: usize>
    StatefulCryptIo<'a, IO, C, BLK_SZ, KEY_SZ>
{
    pub fn new(io: IO, key: Key<KEY_SZ>, crypter: &'a mut C) -> Self {
        Self { io, key, crypter }
    }
}

impl<IO, C, const BLK_SZ: usize, const KEY_SZ: usize> Io
    for StatefulCryptIo<'_, IO, C, BLK_SZ, KEY_SZ>
where
    IO: Io,
{
    type Error = IO::Error;
}

impl<IO, C, const BLK_SZ: usize, const KEY_SZ: usize> Read
    for StatefulCryptIo<'_, IO, C, BLK_SZ, KEY_SZ>
where
    IO: Read + Seek,
    C: StatefulCrypter,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let mut total = 0;
        let mut size = buf.len();

        let origin = self.io.stream_position()?;
        let mut offset = origin as usize;

        // The offset may be within a block. This requires the bytes before the offset in the block
        // and the bytes after the offset to be read.
        if offset % BLK_SZ != 0 {
            let block = offset / BLK_SZ;
            let fill = offset % BLK_SZ;
            let rest = size.min(BLK_SZ - fill);

            let mut tmp_buf = vec![0; (fill + rest) as usize];
            let off = block * BLK_SZ;

            self.io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = self.io.read(&mut tmp_buf)?;
            let actually_read = nbytes - fill;
            if nbytes == 0 || actually_read == 0 {
                self.io.seek(SeekFrom::Start(origin))?;
                return Ok(0);
            }

            self.crypter
                .onetime_decrypt(&self.key, &mut tmp_buf)
                .map_err(|_| ())
                .expect("what");

            buf[..actually_read].copy_from_slice(&tmp_buf[fill..fill + actually_read]);

            offset += actually_read;
            total += actually_read;
            size -= actually_read;
        }

        // At this point, the offset we want to read from is block-aligned. If it isn't, then we
        // must have read all the bytes. Otherwise, read in the rest of the bytes block-by-block.
        while size > 0 && offset % BLK_SZ == 0 {
            let block = offset / BLK_SZ;
            let rest = size.min(BLK_SZ);

            let mut tmp_buf = vec![0; rest];
            let off = block * BLK_SZ;

            self.io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = self.io.read(&mut tmp_buf)?;
            if nbytes == 0 {
                self.io.seek(SeekFrom::Start(origin + total as u64))?;
                return Ok(total);
            }

            self.crypter
                .onetime_decrypt(&self.key, &mut tmp_buf)
                .map_err(|_| ())
                .expect("what");

            buf[total..total + nbytes].copy_from_slice(&tmp_buf[..nbytes]);

            offset += nbytes;
            size -= nbytes;
            total += nbytes;
        }

        self.io.seek(SeekFrom::Start(origin + total as u64))?;

        Ok(total)
    }
}

impl<IO, C, const BLK_SZ: usize, const KEY_SZ: usize> Write
    for StatefulCryptIo<'_, IO, C, BLK_SZ, KEY_SZ>
where
    IO: Read + Write + Seek,
    C: StatefulCrypter,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let mut total = 0;
        let mut size = buf.len();

        let origin = self.io.stream_position()?;
        let mut offset = origin as usize;

        // The write offset may or may not be block-aligned. If it isn't, then the bytes in the
        // block preceding the offset byte should be read as well. The number of bytes to write
        // starting from the offset should be the minimum of the total bytes left to write and the
        // rest of the bytes in the block.
        if offset % BLK_SZ != 0 {
            let block = offset / BLK_SZ;
            let fill = offset % BLK_SZ;
            let rest = size.min(BLK_SZ - fill);

            let mut tmp_buf = vec![0; BLK_SZ];
            let off = block * BLK_SZ;

            self.io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = self.io.read(&mut tmp_buf)?;
            if nbytes == 0 {
                self.io.seek(SeekFrom::Start(origin))?;
                return Ok(0);
            }

            self.crypter
                .onetime_decrypt(&self.key, &mut tmp_buf)
                .map_err(|_| ())
                .expect("what");

            tmp_buf[fill..fill + rest].copy_from_slice(&buf[..rest]);

            self.crypter
                .onetime_encrypt(&self.key, &mut tmp_buf)
                .map_err(|_| ())
                .expect("what");

            let amount = nbytes.max(fill + rest);
            self.io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = self.io.write(&tmp_buf[..amount])?;
            let actually_written = rest.min(nbytes - fill);
            if nbytes == 0 || actually_written == 0 {
                self.io.seek(SeekFrom::Start(origin))?;
                return Ok(0);
            }

            offset += actually_written;
            size -= actually_written;
            total += actually_written;
        }

        // The offset we want to write to should be block-aligned at this point. If not, then we
        // must have written out all the bytes already. Otherwise, write the rest of the bytes
        // block-by-block.
        while size > 0 && size / BLK_SZ > 0 && offset % BLK_SZ == 0 {
            let block = offset / BLK_SZ;

            let mut tmp_buf = buf[total..total + BLK_SZ].to_vec();
            self.crypter
                .onetime_encrypt(&self.key, &mut tmp_buf)
                .map_err(|_| ())
                .expect("what");

            let off = block * BLK_SZ;
            self.io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = self.io.write(&tmp_buf)?;
            if nbytes == 0 {
                self.io.seek(SeekFrom::Start(origin + total as u64))?;
                return Ok(total);
            }

            offset += nbytes;
            size -= nbytes;
            total += nbytes;
        }

        // Write any remaining bytes that don't fill an entire block. We handle this specially
        // since we have to read in the block to decrypt the bytes after the overwritten bytes.
        if size > 0 {
            let block = offset / BLK_SZ;

            // Try to read a whole block.
            let mut tmp_buf = vec![0; BLK_SZ];
            let off = block * BLK_SZ;
            self.io.seek(SeekFrom::Start(off as u64))?;
            let actually_read = self.io.read(&mut tmp_buf)?;
            let actually_write = size.max(actually_read);

            self.crypter
                .onetime_decrypt(&self.key, &mut tmp_buf)
                .map_err(|_| ())
                .expect("what");

            tmp_buf[..size].copy_from_slice(&buf[total..total + size]);

            self.crypter
                .onetime_encrypt(&self.key, &mut tmp_buf)
                .map_err(|_| ())
                .expect("what");

            self.io.seek(SeekFrom::Start(off as u64))?;
            let nbytes = self.io.write(&tmp_buf[..actually_write])?;
            total += size.min(nbytes as usize);

            if nbytes == 0 {
                self.io.seek(SeekFrom::Start(origin + total as u64))?;
                return Ok(total);
            }
        }

        self.io.seek(SeekFrom::Start(origin + total as u64))?;

        Ok(total)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.io.flush()
    }
}

impl<IO, C, const BLK_SZ: usize, const KEY_SZ: usize> Seek
    for StatefulCryptIo<'_, IO, C, BLK_SZ, KEY_SZ>
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
    use hasher::sha3::SHA3_256_MD_SIZE;
    use minimal_io::{
        blocking::{Read, Write},
        stdio::StdIo,
        Seek, SeekFrom,
    };
    use tempfile::NamedTempFile;

    const BLOCK_SIZE: usize = 4096;
    const KEY_SIZE: usize = SHA3_256_MD_SIZE;

    // Writes 4 blocks of 'a's, then 4 'b's at offset 3.
    #[test]
    fn offset_write() -> Result<()> {
        let key = [0; KEY_SIZE];

        let mut blockio = CryptIo::<StdIo<NamedTempFile>, Aes256Ctr, BLOCK_SIZE, KEY_SIZE>::new(
            StdIo::new(NamedTempFile::new()?),
            key,
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
        let key = [0; KEY_SIZE];

        let mut blockio = CryptIo::<StdIo<NamedTempFile>, Aes256Ctr, BLOCK_SIZE, KEY_SIZE>::new(
            StdIo::new(NamedTempFile::new()?),
            key,
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
        let key = [0; KEY_SIZE];

        let mut blockio = CryptIo::<StdIo<NamedTempFile>, Aes256Ctr, BLOCK_SIZE, KEY_SIZE>::new(
            StdIo::new(NamedTempFile::new()?),
            key,
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
        let key = [0; KEY_SIZE];

        let mut blockio = CryptIo::<StdIo<NamedTempFile>, Aes256Ctr, BLOCK_SIZE, KEY_SIZE>::new(
            StdIo::new(NamedTempFile::new()?),
            key,
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
