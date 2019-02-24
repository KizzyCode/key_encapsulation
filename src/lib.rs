//! This crate is an implementation of the KyNc specification (see
//! [Kync.asciidoc](https://github.com/KizzyCode/kync/blob/master/Kync.asciidoc))

mod ffi;
pub mod plugin;

use std::{
	error::Error as StdError,
	fmt::{ Display, Formatter, Result as FmtResult },
	io::{ Error as IoError, ErrorKind as IoErrorKind }
};
pub use crate::{ plugin::Plugin, ffi::{ CSource, AsCSource, CSink, AsCSink } };


/// The error kind
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ErrorKind {
	/// An operation is not permitted (at least not without providing authentication data)
	PermissionDenied{ requires_authentication: bool },
	/// An authentication error occurred (e.g. bad PIN, password etc.); if the amount of retries
	/// left is `None`, this means that there is no limit
	AccessDenied{ retries_left: Option<u64> },
	/// The provided buffer is too small and cannot be resized
	BufferError{ required_size: u64 },
	/// An IO-error occurred
	IoError,
	/// Invalid data
	InvalidData,
	/// There are no crypto items to list (because the plugin has no key store) or there is no
	/// matching algorithm/key available to encrypt/decrypt the capsule
	ItemNotFound,
	/// An invalid parameter was passed
	InvalidParameter{ index: u64 },
	/// The operation was canceled by the user
	OperationCancelled,
	/// The operation timed out (e.g. took longer than 90s)
	OperationTimedOut,
	/// An unspecified plugin error occurred
	OtherPluginError{ errno: u64 },
	/// The operation is unsupported
	Unsupported
}


/// An error
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct KyncError {
	/// The error kind
	pub kind: ErrorKind,
	/// An description of the error
	pub desc: Option<String>
}
impl Display for KyncError {
	fn fmt(&self, f: &mut Formatter) -> FmtResult {
		write!(f, "{:?}", &self.kind)?;
		if let Some(desc) = self.desc.as_ref() { write!(f, " ({:#?})", desc)?; }
		Ok(())
	}
}
impl From<ErrorKind> for KyncError {
	fn from(kind: ErrorKind) -> Self {
		Self{ kind, desc: None }
	}
}
impl<T: ToString> From<(ErrorKind, T)> for KyncError {
	fn from(kind_desc: (ErrorKind, T)) -> Self {
		Self{ kind: kind_desc.0, desc: Some(kind_desc.1.to_string()) }
	}
}
impl From<IoErrorKind> for KyncError {
	fn from(io_error_kind: IoErrorKind) -> Self {
		Self{ kind: ErrorKind::IoError, desc: Some(format!("{:#?}", io_error_kind)) }
	}
}
impl From<IoError> for KyncError {
	fn from(io_error: IoError) -> Self {
		Self{ kind: ErrorKind::IoError, desc: Some(format!("{}", io_error)) }
	}
}
impl StdError for KyncError {}