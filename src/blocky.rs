use embedded_io::{
    blocking::{Read, Seek, Write},
    Io, SeekFrom,
};

pub struct BlockIo<IO> {
    pub(crate) io: IO,
    iv_len: usize,
    block_size: usize,
}

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

impl<IO> BlockIo<IO>
where
    IO: Seek,
{
    // Creates a new `BlockIo`.
    pub fn new(io: IO, iv_len: usize, block_size: usize) -> Self {
        Self {
            io,
            iv_len,
            block_size,
        }
    }

    // Returns if the underlying IO is aligned to a block boundary.
    pub fn is_aligned(&self, offset: u64) -> bool {
        self.padding(offset) == 0
    }

    /// Returns the current block number.
    pub fn curr_block(&self, offset: u64) -> u64 {
        offset / self.block_size as u64
    }

    /// Returns the block size.
    pub fn padded_block_size(&self) -> u64 {
        (self.block_size + self.iv_len) as u64
    }

    // Aligns `offset` to the start of its block.
    fn align(&self, offset: u64) -> u64 {
        (offset / self.block_size as u64) * self.padded_block_size()
    }

    // Returns the distance, in bytes, from `offset` to the start of its block.
    fn padding(&self, offset: u64) -> u64 {
        offset % self.block_size as u64
    }

    /// Returns the distance, in bytes, from `offset` to the IV at the start of the block.
    fn fill(&self, offset: u64) -> u64 {
        offset - (self.curr_block(offset) * self.block_size as u64)
    }

    // Extracts out the IV.
    fn extract_iv(&self, mut raw: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        (raw.drain(..self.iv_len).collect(), raw)
    }

    // Reads a block.
    pub fn read_block(&mut self, pos: u64) -> Result<Block, IO::Error>
    where
        IO: Read,
    {
        let offset = self.align(pos);
        let padding = self.padding(pos);
        let fill = self.fill(pos);

        self.io.seek(SeekFrom::Start(offset))?;

        let mut raw = vec![0; self.padded_block_size() as usize];
        let nbytes = self.io.read(&mut raw)?;

        // Restore seek cursor if we didn't read anything.
        if nbytes == 0 || nbytes < padding as usize + self.iv_len {
            self.io.seek(SeekFrom::Start(pos))?;
            return Ok(Block::Empty);
        }

        raw.truncate(nbytes);

        let (iv, data) = self.extract_iv(raw);

        // eprintln!(
        //     "rblock: block={}, iv={}, data={}",
        //     self.curr_block(offset),
        //     hex::encode(&iv),
        //     hex::encode(&data)
        // );

        if padding != 0 {
            Ok(Block::Unaligned {
                iv,
                data,
                fill: fill as usize,
            })
        } else {
            Ok(Block::Aligned { iv, data })
        }
    }

    // Writes a block.
    pub fn write_block(&mut self, pos: u64, iv: &[u8], data: &[u8]) -> Result<usize, IO::Error>
    where
        IO: Write,
    {
        let offset = self.align(pos);

        self.io.seek(SeekFrom::Start(offset))?;

        // eprintln!(
        //     "wblock: block={}, iv={}, data={}",
        //     self.curr_block(offset),
        //     hex::encode(&iv),
        //     hex::encode(&data)
        // );

        self.io.write(&iv)?;

        Ok(self.io.write(&data)?)
    }
}

impl<IO> Io for BlockIo<IO>
where
    IO: Io,
{
    type Error = IO::Error;
}

impl<IO> Seek for BlockIo<IO>
where
    IO: Seek,
{
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, Self::Error> {
        self.io.seek(pos)
    }
}
