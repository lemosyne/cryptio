use crate::{IvGenerator, Key};
use crypter::StatefulCrypter;
use embedded_io::{
    blocking::{Read, ReadAt, ReadExactAtError, ReadExactError, Seek, Write, WriteAt},
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

impl<'a, IO: Io, G, C, const KEY_SZ: usize> Io for OneshotCryptIo<'a, IO, G, C, KEY_SZ> {
    type Error = IO::Error;
}

impl<'a, IO, G, C, const KEY_SZ: usize> Read for OneshotCryptIo<'a, IO, G, C, KEY_SZ>
where
    IO: Read + Seek,
    C: StatefulCrypter,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IO::Error> {
        let start_pos = self.io.stream_position()?;

        // Read the current iv
        let mut iv = Vec::with_capacity(C::iv_length());
        self.io.seek(SeekFrom::Start(0))?;
        match self.io.read_exact(&mut iv) {
            Ok(()) => {}
            Err(ReadExactError::Other(e)) => return Err(e),
            Err(_) => {
                self.io.seek(SeekFrom::Start(start_pos))?;
                return Ok(0);
            }
        };

        // Read the desired data's ciphertext
        // TODO: verify that this is correct, maybe decrypt could require
        // more than buf.len() bytes or produce a smaller plaintext
        self.io.seek(SeekFrom::Start(start_pos))?;
        let mut scratch = vec![0; buf.len()];
        let n = self.io.read(&mut scratch)?;

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
        let cn = self.io.read_to_end(buf)?;
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
    fn read_at(&mut self, buf: &mut [u8], offset: u64) -> Result<usize, IO::Error> {
        let start_pos = offset;

        // Read the current iv
        let mut iv = Vec::with_capacity(C::iv_length());
        match self.io.read_exact_at(&mut iv, 0) {
            Ok(()) => {}
            Err(ReadExactAtError::Other(e)) => return Err(e),
            Err(_) => {
                return Ok(0);
            }
        };

        // Read the desired data's ciphertext
        // TODO: verify that this is correct, maybe decrypt could require
        // more than buf.len() bytes or produce a smaller plaintext
        let mut scratch = vec![0; buf.len()];
        let n = self.io.read_at(&mut scratch, start_pos)?;

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

    fn read_to_end_at(&mut self, buf: &mut Vec<u8>, offset: u64) -> Result<usize, Self::Error> {
        // Read the complete iv + ciphertext
        let cn = self.io.read_to_end_at(buf, offset)?;
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

impl<'a, IO, G, C, const KEY_SZ: usize> Write for OneshotCryptIo<'a, IO, G, C, KEY_SZ>
where
    IO: Read + Write + Seek,
    G: IvGenerator,
    C: StatefulCrypter,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        // TODO: this implementation is lazzzzy

        let start_pos = self.io.stream_position()?;

        // Read the currently existent iv + ciphertext
        let mut data = Vec::new();
        self.io.seek(SeekFrom::Start(0))?;
        let cn = self.io.read_to_end(&mut data)?;

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
            let sub_end = pt.len().max(start_pos as usize + buf.len());
            let diff = sub_end - start_pos as usize;
            pt[start_pos as usize..sub_end].copy_from_slice(&buf[..diff]);
            pt.extend(&buf[diff..]);

            pt
        };

        // Generate the new IV.
        let mut new_iv = vec![0; C::iv_length()];
        self.ivg.generate_iv(&mut new_iv).map_err(|_| ()).unwrap();

        self.io.seek(SeekFrom::Start(0))?;
        self.io.write_all(&new_iv)?;

        // Encrypt the plaintext and write it.
        self.crypter
            .encrypt(&self.key, &new_iv, &mut plaintext)
            .map_err(|_| ())
            .unwrap();

        self.io.write_all(&plaintext)?;

        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.io.flush()
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
        let cn = self.io.read_to_end_at(&mut data, 0)?;

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
            let sub_end = pt.len().max(start_pos as usize + buf.len());
            let diff = sub_end - start_pos as usize;
            pt[start_pos as usize..sub_end].copy_from_slice(&buf[..diff]);
            pt.extend(&buf[diff..]);

            pt
        };

        // Generate the new IV.
        let mut new_iv = vec![0; C::iv_length()];
        self.ivg.generate_iv(&mut new_iv).map_err(|_| ()).unwrap();
        self.io.write_all_at(&new_iv, 0)?;

        // Encrypt the plaintext and write it.
        self.crypter
            .encrypt(&self.key, &new_iv, &mut plaintext)
            .map_err(|_| ())
            .unwrap();

        self.io.write_all_at(&plaintext, new_iv.len() as u64)?;

        Ok(buf.len())
    }
}

impl<'a, IO, R, C, const KEY_SZ: usize> Seek for OneshotCryptIo<'a, IO, R, C, KEY_SZ>
where
    IO: Seek,
{
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, Self::Error> {
        self.io.seek(pos)
    }
}
