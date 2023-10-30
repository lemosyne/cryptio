//! A collection of encrypted IO handles.

pub mod block;
pub mod full;

pub(crate) type Key<const N: usize> = [u8; N];
