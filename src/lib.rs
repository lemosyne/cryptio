//! A collection of encrypted IO handles.

pub(crate) type Key<const N: usize> = [u8; N];

pub mod block;
pub mod crypt;
pub mod iv;
pub mod padded;
pub mod recrypt;
