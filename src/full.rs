use crate::{IvGenerator, Key};
use crypter::StatefulCrypter;
use minimal_io::{
    blocking::{Read, ReadAt, Seek, Write, WriteAt},
    Io, SeekFrom,
};

pub enum Block {
    Empty,
    Unaligned { real: usize, fill: usize },
    Aligned { real: usize },
}

pub struct IvCryptIo<'a, IO, G, C, const BLK_SZ: usize, const KEY_SZ: usize> {
    pub io: IO,
    key: Key<KEY_SZ>,
    ivg: &'a mut G,
    crypter: &'a mut C,
}

impl<'a, IO, G, C, const BLK_SZ: usize, const KEY_SZ: usize> IvCryptIo<'a, IO, G, C, BLK_SZ, KEY_SZ>
where
    IO: Io,
    C: StatefulCrypter,
{
    pub fn new(io: IO, key: Key<KEY_SZ>, ivg: &'a mut G, crypter: &'a mut C) -> Self
    where
        C: Default,
    {
        Self {
            io,
            key,
            ivg,
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
        IO: Read + Write + Seek,
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

impl<'a, IO: Io, R, C, const BLK_SZ: usize, const KEY_SZ: usize> Io
    for IvCryptIo<'a, IO, R, C, BLK_SZ, KEY_SZ>
{
    type Error = IO::Error;
}

impl<'a, IO, G, C, const BLK_SZ: usize, const KEY_SZ: usize> Read
    for IvCryptIo<'a, IO, G, C, BLK_SZ, KEY_SZ>
where
    IO: Read + Seek,
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
                    let (iv, data) = scratch.split_at_mut(C::iv_length());

                    self.crypter
                        .decrypt(&self.key, iv, data)
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
                    let (iv, data) = scratch.split_at_mut(C::iv_length());

                    self.crypter
                        .decrypt(&self.key, iv, data)
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

impl<'a, IO, G, C, const BLK_SZ: usize, const KEY_SZ: usize> ReadAt
    for IvCryptIo<'a, IO, G, C, BLK_SZ, KEY_SZ>
where
    IO: ReadAt,
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
                    let (iv, data) = scratch.split_at_mut(C::iv_length());

                    self.crypter
                        .decrypt(&self.key, iv, data)
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
                    let (iv, data) = scratch.split_at_mut(C::iv_length());

                    self.crypter
                        .decrypt(&self.key, iv, data)
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

impl<'a, IO, G, C, const BLK_SZ: usize, const KEY_SZ: usize> Write
    for IvCryptIo<'a, IO, G, C, BLK_SZ, KEY_SZ>
where
    IO: Read + Write + Seek,
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
                        self.io.seek(SeekFrom::Start(offset as u64))?;
                        return Ok(total);
                    }
                    Block::Unaligned { real, fill } => {
                        let (iv, data) = scratch.split_at_mut(C::iv_length());

                        // Decrypt the bytes we read.
                        self.crypter
                            .decrypt(&self.key, iv, &mut data[..real])
                            .map_err(|_| ())
                            .unwrap();

                        // Add in the bytes that we're writing, up until a block boundary.
                        let rest = size.min(data.len() - fill);
                        data[fill..fill + rest].copy_from_slice(&buf[total..total + rest]);

                        // Generate a new IV.
                        self.ivg.generate_iv(iv).map_err(|_| ()).unwrap();

                        self.crypter
                            .encrypt(&self.key, iv, data)
                            .map_err(|_| ())
                            .unwrap();

                        // Write the IV and ciphertext.
                        // The amount of bytes could exceed what was there originally (real).
                        let amount = real.max(fill + rest);
                        let nbytes = self.write_block(offset, &iv, &data[..amount])?;
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
                let (iv, _data) = scratch.split_at_mut(C::iv_length());

                // Copy data to a scratch block buffer for encryption.
                scratch_block.copy_from_slice(&buf[total..total + BLK_SZ]);

                // Encrypt the data with a new IV.
                self.ivg.generate_iv(iv).map_err(|_| ()).unwrap();

                self.crypter
                    .encrypt(&self.key, &iv, &mut scratch_block)
                    .map_err(|_| ())
                    .unwrap();

                // Write the IV and ciphertext.
                let nbytes = self.write_block(offset, iv, &scratch_block)?;
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
                        let (iv, _data) = scratch.split_at_mut(C::iv_length());

                        // Copy over the bytes to the scratch buffer for encryption.
                        scratch_block[..size].copy_from_slice(&buf[total..total + size]);

                        // Encrypt the remaining bytes.
                        self.ivg.generate_iv(iv).map_err(|_| ()).unwrap();

                        self.crypter
                            .encrypt(&self.key, iv, &mut scratch_block[..size])
                            .map_err(|_| ())
                            .unwrap();

                        // Write the block.
                        let nbytes = self.write_block(offset, iv, &scratch_block[..size])?;
                        if nbytes == 0 {
                            self.io.seek(SeekFrom::Start(offset as u64))?;
                            return Ok(total);
                        }

                        total += nbytes;
                        offset += nbytes;
                        size -= nbytes;
                    }
                    // We need to rewrite any bytes trailing the overwritten bytes.
                    Block::Aligned { real } => {
                        let (iv, data) = scratch.split_at_mut(C::iv_length());

                        self.crypter
                            .decrypt(&self.key, iv, data)
                            .map_err(|_| ())
                            .unwrap();

                        // Copy in the bytes that we want to update.
                        data[..size].copy_from_slice(&buf[total..total + size]);

                        // Encrypt the plaintext.
                        self.ivg.generate_iv(iv).map_err(|_| ()).unwrap();

                        self.crypter
                            .encrypt(&self.key, iv, data)
                            .map_err(|_| ())
                            .unwrap();

                        // Write the block.
                        let nbytes = self.write_block(offset, iv, &data[..size.max(real)])?;
                        if nbytes == 0 {
                            self.io.seek(SeekFrom::Start(offset as u64))?;
                            return Ok(total);
                        }

                        total += nbytes;
                        offset += nbytes;
                        size -= nbytes;
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

impl<'a, IO, G, C, const BLK_SZ: usize, const KEY_SZ: usize> WriteAt
    for IvCryptIo<'a, IO, G, C, BLK_SZ, KEY_SZ>
where
    IO: ReadAt + WriteAt,
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
                        let (iv, data) = scratch.split_at_mut(C::iv_length());

                        // Decrypt the bytes we read.
                        self.crypter
                            .decrypt(&self.key, iv, &mut data[..real])
                            .map_err(|_| ())
                            .unwrap();

                        // Add in the bytes that we're writing, up until a block boundary.
                        let rest = size.min(data.len() - fill);
                        data[fill..fill + rest].copy_from_slice(&buf[total..total + rest]);

                        // Generate a new IV.
                        self.ivg.generate_iv(iv).map_err(|_| ()).unwrap();

                        self.crypter
                            .encrypt(&self.key, iv, data)
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
                let (iv, _data) = scratch.split_at_mut(C::iv_length());

                // Copy data to a scratch block buffer for encryption.
                scratch_block.copy_from_slice(&buf[total..total + BLK_SZ]);

                // Encrypt the data with a new IV.
                self.ivg.generate_iv(iv).map_err(|_| ()).unwrap();

                self.crypter
                    .encrypt(&self.key, &iv, &mut scratch_block)
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
                        let (iv, _data) = scratch.split_at_mut(C::iv_length());

                        // Copy over the bytes to the scratch buffer for encryption.
                        scratch_block[..size].copy_from_slice(&buf[total..total + size]);

                        // Encrypt the remaining bytes.
                        self.ivg.generate_iv(iv).map_err(|_| ()).unwrap();

                        self.crypter
                            .encrypt(&self.key, iv, &mut scratch_block[..size])
                            .map_err(|_| ())
                            .unwrap();

                        // Write the block.
                        let nbytes = self.write_block_at(offset, iv, &scratch_block[..size])?;
                        if nbytes == 0 {
                            return Ok(total);
                        }

                        total += nbytes;
                        offset += nbytes;
                        size -= nbytes;
                    }
                    // We need to rewrite any bytes trailing the overwritten bytes.
                    Block::Aligned { real } => {
                        let (iv, data) = scratch.split_at_mut(C::iv_length());

                        self.crypter
                            .decrypt(&self.key, iv, data)
                            .map_err(|_| ())
                            .unwrap();

                        // Copy in the bytes that we want to update.
                        data[..size].copy_from_slice(&buf[total..total + size]);

                        // Encrypt the plaintext.
                        self.ivg.generate_iv(iv).map_err(|_| ()).unwrap();

                        self.crypter
                            .encrypt(&self.key, iv, data)
                            .map_err(|_| ())
                            .unwrap();

                        // Write the block.
                        let nbytes = self.write_block_at(offset, iv, &data[..size.max(real)])?;
                        if nbytes == 0 {
                            return Ok(total);
                        }

                        total += nbytes;
                        offset += nbytes;
                        size -= nbytes;
                    }
                    _ => {
                        panic!("shouldn't be performing an unaligned write");
                    }
                }
            }
        }

        Ok(total)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.io.flush()
    }
}

impl<'a, IO, R, C, const BLK_SZ: usize, const KEY_SZ: usize> Seek
    for IvCryptIo<'a, IO, R, C, BLK_SZ, KEY_SZ>
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
    use crypter::aes::Aes256Ctr;
    use minimal_io::stdio::StdIo;
    use rand::{rngs::ThreadRng, RngCore};
    use tempfile::NamedTempFile;

    const KEY_SIZE: usize = 32;
    const BLOCK_SIZE: usize = 4096;

    #[test]
    fn it_works() -> Result<()> {
        let mut rng = ThreadRng::default();
        let mut ivg = SequentialIvGenerator::new(16);
        let mut crypter = Aes256Ctr::new();

        let mut key = [0; KEY_SIZE];
        rng.fill_bytes(&mut key);

        let mut io = IvCryptIo::<
            StdIo<NamedTempFile>,
            SequentialIvGenerator,
            Aes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            StdIo::new(NamedTempFile::new()?),
            key,
            &mut ivg,
            &mut crypter,
        );

        let data1 = vec!['a' as u8; 8192];
        io.seek(SeekFrom::Start(0))?;
        io.write_all(&data1)?;

        let mut data2 = vec![];
        io.seek(SeekFrom::Start(0))?;
        io.read_to_end(&mut data2)?;

        assert_eq!(data1, data2);

        Ok(())
    }

    #[test]
    fn it_works_at() -> Result<()> {
        let mut rng = ThreadRng::default();
        let mut ivg = SequentialIvGenerator::new(16);
        let mut crypter = Aes256Ctr::new();

        let mut key = [0; KEY_SIZE];
        rng.fill_bytes(&mut key);

        let mut io = IvCryptIo::<
            StdIo<NamedTempFile>,
            SequentialIvGenerator,
            Aes256Ctr,
            BLOCK_SIZE,
            KEY_SIZE,
        >::new(
            StdIo::new(NamedTempFile::new()?),
            key,
            &mut ivg,
            &mut crypter,
        );

        let data1 = vec!['a' as u8; 8192];
        io.write_all_at(&data1, 0)?;

        let mut data2 = vec![];
        io.read_to_end_at(&mut data2, 0)?;

        assert_eq!(data1, data2);

        Ok(())
    }
}
