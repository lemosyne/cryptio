use std::convert::Infallible;

use crate::{error::Error, IvGenerator, Key};
use crypter::StatefulCrypter;
use minimal_io::{
    blocking::{Read, ReadAt, ReadExactError, Seek, Write, WriteAt},
    Io, SeekFrom,
};

/// You should probably only use this writing or reading
/// the entiriety of IO (or with a BufReader),
/// as it uses one IV and thus usually requires a full read/write anyways
pub struct OneshotCryptIo<'a, IO, G, C, const KEY_SZ: usize> {
    pub io: IO,
    key: Key<KEY_SZ>,
    ivg: &'a mut G,
    crypter: &'a mut C,
}

impl<'a, IO, G, C, const KEY_SZ: usize> OneshotCryptIo<'a, IO, G, C, KEY_SZ> {
    pub fn new(io: IO, key: Key<KEY_SZ>, ivg: &'a mut G, crypter: &'a mut C) -> Self {
        Self {
            io,
            key,
            ivg,
            crypter,
        }
    }
}

impl<'a, IO: Io, G, C, const KEY_SZ: usize> Io for OneshotCryptIo<'a, IO, G, C, KEY_SZ>
where
    C: StatefulCrypter,
    IO: Io,
    G: IvGenerator,
{
    type Error = Error<C::Error, IO::Error, G::Error, Infallible>;
}

impl<'a, IO, G, C, const KEY_SZ: usize> Read for OneshotCryptIo<'a, IO, G, C, KEY_SZ>
where
    C: StatefulCrypter,
    IO: Read + Seek,
    G: IvGenerator,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let start_pos = self.io.stream_position().map_err(Error::Inner)?;

        // Read the current iv
        let mut iv = Vec::with_capacity(C::iv_length());
        self.io.seek(SeekFrom::Start(0)).map_err(Error::Inner)?;
        match self.io.read_exact(&mut iv) {
            Ok(()) => {}
            Err(ReadExactError::Other(e)) => return Err(Error::Inner(e)),
            Err(_) => {
                self.io
                    .seek(SeekFrom::Start(start_pos))
                    .map_err(Error::Inner)?;
                return Ok(0);
            }
        };

        // Read the desired data's ciphertext
        // TODO: verify that this is correct, maybe decrypt could require
        // more than buf.len() bytes or produce a smaller plaintext
        self.io
            .seek(SeekFrom::Start(start_pos))
            .map_err(Error::Inner)?;
        let mut scratch = vec![0; buf.len()];
        let n = self.io.read(&mut scratch).map_err(Error::Inner)?;

        // Decrypt the ciphertext and copy it back into buf
        // let plaintext = C::decrypt(&self.key, &iv, buf).map_err(|_| ()).unwrap();
        // buf.copy_from_slice(&plaintext);
        self.crypter
            .decrypt(&self.key, &iv, &mut scratch)
            .map_err(|_| ())
            .unwrap();
        buf.copy_from_slice(&scratch);

        Ok(n)
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Result<usize, Self::Error> {
        // Read the complete iv + ciphertext
        let cn = self.io.read_to_end(buf).map_err(Error::Inner)?;
        if cn < C::iv_length() {
            return Ok(0);
        }

        // Decrypt it
        // let iv = buf[..C::iv_length()].to_vec();
        // let plaintext = C::decrypt(&self.key, &iv, &mut buf[C::iv_length()..])
        //     .map_err(|_| ())
        //     .unwrap();
        let (iv, pt) = buf.split_at_mut(C::iv_length());
        self.crypter
            .decrypt(&self.key, iv, pt)
            .map_err(|_| ())
            .unwrap();

        // Copy the plaintext back into buf
        *buf = pt.to_vec();

        Ok(buf.len())
    }
}

impl<'a, IO, G, C, const KEY_SZ: usize> ReadAt for OneshotCryptIo<'a, IO, G, C, KEY_SZ>
where
    IO: ReadAt,
    G: IvGenerator,
    C: StatefulCrypter,
{
    fn read_at(&mut self, buf: &mut [u8], offset: u64) -> Result<usize, Self::Error> {
        let start_pos = offset;

        // Read the current iv
        let mut iv = Vec::with_capacity(C::iv_length());
        match self.io.read_exact_at(&mut iv, 0) {
            Ok(()) => {}
            Err(ReadExactError::Other(e)) => return Err(Error::Inner(e)),
            Err(_) => {
                return Ok(0);
            }
        };

        // Read the desired data's ciphertext
        // TODO: verify that this is correct, maybe decrypt could require
        // more than buf.len() bytes or produce a smaller plaintext
        let mut scratch = vec![0; buf.len()];
        let n = self
            .io
            .read_at(&mut scratch, start_pos)
            .map_err(Error::Inner)?;

        // Decrypt the ciphertext and copy it back into buf
        self.crypter
            .decrypt(&self.key, &iv, &mut scratch)
            .map_err(|_| ())
            .unwrap();
        buf.copy_from_slice(&scratch);

        Ok(n)
    }

    fn read_to_end_at(&mut self, buf: &mut Vec<u8>, offset: u64) -> Result<usize, Self::Error> {
        // Read the complete iv + ciphertext
        let cn = self.io.read_to_end_at(buf, offset).map_err(Error::Inner)?;
        if cn < C::iv_length() {
            return Ok(0);
        }

        // Decrypt it
        let (iv, pt) = buf.split_at_mut(C::iv_length());
        self.crypter
            .decrypt(&self.key, iv, pt)
            .map_err(Error::Crypt)?;

        // Copy the plaintext back into buf
        *buf = pt.to_vec();

        Ok(buf.len())
    }
}

impl<'a, IO, G, C, const KEY_SZ: usize> Write for OneshotCryptIo<'a, IO, G, C, KEY_SZ>
where
    IO: Read + Write + Seek,
    G: IvGenerator,
    C: StatefulCrypter,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        // TODO: this implementation is lazzzzy

        let start_pos = self.io.stream_position().map_err(Error::Inner)?;

        // Read the currently existent iv + ciphertext
        let mut data = Vec::new();
        self.io.seek(SeekFrom::Start(0)).map_err(Error::Inner)?;
        let cn = self.io.read_to_end(&mut data).map_err(Error::Inner)?;

        let mut plaintext = if cn <= C::iv_length() {
            // If the initial file was too empty, then the plaintext is just buf.
            buf.to_vec()
        } else {
            // Otherwise, decrypt the ciphertext.
            let (iv, ct) = data.split_at_mut(C::iv_length());

            self.crypter
                .decrypt(&self.key, iv, ct)
                .map_err(|_| ())
                .unwrap();

            let mut pt = ct.to_vec();

            // And substitute in the to-be-written data
            let sub_bytes = buf.len().min(pt.len() - start_pos as usize);
            pt[start_pos as usize..start_pos as usize + sub_bytes]
                .copy_from_slice(&buf[..sub_bytes]);
            pt.extend(&buf[sub_bytes..]);

            pt
        };

        // Generate the new IV.
        let mut new_iv = vec![0; C::iv_length()];
        self.ivg.generate_iv(&mut new_iv).map_err(|_| ()).unwrap();

        self.io.seek(SeekFrom::Start(0)).map_err(Error::Inner)?;
        self.io.write_all(&new_iv).map_err(Error::InnerWriteAll)?;

        // Encrypt the plaintext and write it.
        self.crypter
            .encrypt(&self.key, &new_iv, &mut plaintext)
            .map_err(Error::Crypt)?;

        self.io
            .write_all(&plaintext)
            .map_err(Error::InnerWriteAll)?;

        // Restore cursor position.
        self.io
            .seek(SeekFrom::Start(start_pos + buf.len() as u64))
            .map_err(Error::Inner)?;

        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.io.flush().map_err(Error::Inner)
    }
}

impl<'a, IO, G, C, const KEY_SZ: usize> WriteAt for OneshotCryptIo<'a, IO, G, C, KEY_SZ>
where
    IO: ReadAt + WriteAt,
    G: IvGenerator,
    C: StatefulCrypter,
{
    fn write_at(&mut self, buf: &[u8], offset: u64) -> Result<usize, Self::Error> {
        // TODO: this implementation is lazzzzy

        let start_pos = offset;

        // Read the currently existent iv + ciphertext
        let mut data = Vec::new();
        let cn = self.io.read_to_end_at(&mut data, 0).map_err(Error::Inner)?;

        let mut plaintext = if cn <= C::iv_length() {
            // If the initial file was too empty, then the plaintext is just buf.
            buf.to_vec()
        } else {
            // Otherwise, decrypt the ciphertext.
            let (iv, ct) = data.split_at_mut(C::iv_length());

            // plaintext_b =
            //     C::decrypt(&self.key, &data[..C::iv_length()], &data[C::iv_length()..])
            //         .map_err(|_| ())
            //         .unwrap();
            self.crypter
                .decrypt(&self.key, iv, ct)
                .map_err(|_| ())
                .unwrap();

            let mut pt = ct.to_vec();

            // And substitute in the to-be-written data
            let sub_bytes = buf.len().min(pt.len() - start_pos as usize);
            pt[start_pos as usize..start_pos as usize + sub_bytes]
                .copy_from_slice(&buf[..sub_bytes]);
            pt.extend(&buf[sub_bytes..]);

            pt
        };

        // Generate the new IV.
        let mut new_iv = vec![0; C::iv_length()];
        self.ivg.generate_iv(&mut new_iv).map_err(|_| ()).unwrap();
        self.io
            .write_all_at(&new_iv, 0)
            .map_err(Error::InnerWriteAll)?;

        // Encrypt the plaintext and write it.
        self.crypter
            .encrypt(&self.key, &new_iv, &mut plaintext)
            .map_err(Error::Crypt)?;

        self.io
            .write_all_at(&plaintext, new_iv.len() as u64)
            .map_err(Error::InnerWriteAll)?;

        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.io.flush().map_err(Error::Inner)
    }
}

impl<'a, IO, G, C, const KEY_SZ: usize> Seek for OneshotCryptIo<'a, IO, G, C, KEY_SZ>
where
    C: StatefulCrypter,
    IO: Seek,
    G: IvGenerator,
{
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, Self::Error> {
        self.io.seek(pos).map_err(Error::Inner)
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

    #[test]
    fn oneshot() -> Result<()> {
        let mut rng = ThreadRng::default();
        let mut ivg = SequentialIvGenerator::new(16);
        let mut crypter = Aes256Ctr::new();

        let mut key = [0; KEY_SIZE];
        rng.fill_bytes(&mut key);

        let mut io = OneshotCryptIo::<
            StdIo<NamedTempFile>,
            SequentialIvGenerator,
            Aes256Ctr,
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
    fn oneshot_at() -> Result<()> {
        let mut rng = ThreadRng::default();
        let mut ivg = SequentialIvGenerator::new(16);
        let mut crypter = Aes256Ctr::new();

        let mut key = [0; KEY_SIZE];
        rng.fill_bytes(&mut key);

        let mut io = OneshotCryptIo::<
            StdIo<NamedTempFile>,
            SequentialIvGenerator,
            Aes256Ctr,
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

    #[test]
    fn overwrite() -> Result<()> {
        let mut rng = ThreadRng::default();
        let mut ivg = SequentialIvGenerator::new(16);
        let mut crypter = Aes256Ctr::new();

        let mut key = [0; KEY_SIZE];
        rng.fill_bytes(&mut key);

        let mut io = OneshotCryptIo::<
            StdIo<NamedTempFile>,
            SequentialIvGenerator,
            Aes256Ctr,
            KEY_SIZE,
        >::new(
            StdIo::new(NamedTempFile::new()?),
            key,
            &mut ivg,
            &mut crypter,
        );

        let xs = vec!['a' as u8; 8192];
        let ys = vec!['b' as u8; 8192];

        io.seek(SeekFrom::Start(0))?;
        io.write_all(&xs)?;

        io.seek(SeekFrom::Start(3))?;
        io.write_all(&ys)?;

        let mut data = vec![];
        io.seek(SeekFrom::Start(0))?;
        io.read_to_end(&mut data)?;

        assert_eq!(&data[0..3], &xs[0..3]);
        assert_eq!(&data[3..], &ys);
        assert_eq!(data.len(), ys.len() + 3);

        Ok(())
    }

    #[test]
    fn overwrite_at() -> Result<()> {
        let mut rng = ThreadRng::default();
        let mut ivg = SequentialIvGenerator::new(16);
        let mut crypter = Aes256Ctr::new();

        let mut key = [0; KEY_SIZE];
        rng.fill_bytes(&mut key);

        let mut io = OneshotCryptIo::<
            StdIo<NamedTempFile>,
            SequentialIvGenerator,
            Aes256Ctr,
            KEY_SIZE,
        >::new(
            StdIo::new(NamedTempFile::new()?),
            key,
            &mut ivg,
            &mut crypter,
        );

        let xs = vec!['a' as u8; 8192];
        let ys = vec!['b' as u8; 8192];

        io.write_all_at(&xs, 0)?;
        io.write_all_at(&ys, 3)?;

        let mut data = vec![];
        io.read_to_end_at(&mut data, 0)?;

        assert_eq!(&data[0..3], &xs[0..3]);
        assert_eq!(&data[3..], &ys);
        assert_eq!(data.len(), ys.len() + 3);

        Ok(())
    }

    #[test]
    fn append() -> Result<()> {
        let mut rng = ThreadRng::default();
        let mut ivg = SequentialIvGenerator::new(16);
        let mut crypter = Aes256Ctr::new();

        let mut key = [0; KEY_SIZE];
        rng.fill_bytes(&mut key);

        let mut io = OneshotCryptIo::<
            StdIo<NamedTempFile>,
            SequentialIvGenerator,
            Aes256Ctr,
            KEY_SIZE,
        >::new(
            StdIo::new(NamedTempFile::new()?),
            key,
            &mut ivg,
            &mut crypter,
        );

        let xs = vec!['a' as u8; 8192];
        let ys = vec!['b' as u8; 8192];

        io.seek(SeekFrom::Start(0))?;
        io.write_all(&xs)?;
        io.write_all(&ys)?;

        let mut data = vec![];
        io.seek(SeekFrom::Start(0))?;
        io.read_to_end(&mut data)?;

        assert_eq!(&data[..xs.len()], &xs);
        assert_eq!(&data[xs.len()..], &ys);
        assert_eq!(data.len(), xs.len() + ys.len());

        Ok(())
    }

    #[test]
    fn append_at() -> Result<()> {
        let mut rng = ThreadRng::default();
        let mut ivg = SequentialIvGenerator::new(16);
        let mut crypter = Aes256Ctr::new();

        let mut key = [0; KEY_SIZE];
        rng.fill_bytes(&mut key);

        let mut io = OneshotCryptIo::<
            StdIo<NamedTempFile>,
            SequentialIvGenerator,
            Aes256Ctr,
            KEY_SIZE,
        >::new(
            StdIo::new(NamedTempFile::new()?),
            key,
            &mut ivg,
            &mut crypter,
        );

        let xs = vec!['a' as u8; 8192];
        let ys = vec!['b' as u8; 8192];

        io.write_all_at(&xs, 0)?;
        io.write_all_at(&ys, xs.len() as u64)?;

        let mut data = vec![];
        io.read_to_end_at(&mut data, 0)?;

        assert_eq!(&data[..xs.len()], &xs);
        assert_eq!(&data[xs.len()..], &ys);
        assert_eq!(data.len(), xs.len() + ys.len());

        Ok(())
    }
}
