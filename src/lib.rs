//! This crate is an implementation of the KyNc specification (see
//! [Kync.asciidoc](https://github.com/KizzyCode/kync/blob/master/Kync.asciidoc))

/// Some FFI helpers
mod ffi;
/// A key capsule plugin (see "Kync.asciidoc" for further API documentation) and some helpers
pub mod plugin;

use std::{
	io, error::Error, ffi::CStr, os::raw::c_char,
	fmt::{ self, Display, Formatter }
};
use crate::ffi::StaticCharPtrExt;
pub use plugin::Plugin;


/// A plugin error kind
#[derive(Debug)]
pub enum KyncErrorKind {
	/// Failed to load the library
	LoadingError,
	/// The `init`-call failed
	InitError,
	/// The `id`-call failed
	IdError,
	/// The `configs`-call failed
	ConfigsError,
	/// The `auth_info`-call failed
	AuthInfoError,
	/// The `set_context`-call failed
	SetContextError,
	/// The `protect`-call failed
	ProtectError,
	/// The `recover`-call failed
	RecoverError
}
/// A KyNc error
#[derive(Debug)]
pub struct KyncError(KyncErrorKind, &'static CStr);
impl From<io::Error> for KyncError {
	fn from(_: io::Error) -> Self {
		const DESC: *const c_char = b"Failed to load library\0".as_ptr().cast();
		DESC.check(KyncErrorKind::LoadingError).unwrap_err()
	}
}
impl Display for KyncError {
	fn fmt(&self, f: &mut Formatter) -> fmt::Result {
		write!(f, "{:?}", self)
	}
}
impl Error for KyncError {}