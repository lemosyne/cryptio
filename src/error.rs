use minimal_io::blocking::{ReadExactError, WriteAllError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error<C, IO, G, KMS> {
    #[error(transparent)]
    Crypt(C),

    #[error(transparent)]
    IV(G),

    #[error(transparent)]
    KMS(KMS),

    #[error(transparent)]
    Inner(IO),

    #[error(transparent)]
    InnerReadExact(ReadExactError<IO>),

    #[error(transparent)]
    InnerWriteAll(WriteAllError<IO>),
}
