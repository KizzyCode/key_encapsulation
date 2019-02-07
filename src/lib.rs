//! This crate is an implementation of the Kync specification (see "Kync.asciidoc")

mod ffi;
mod plugin;

use std::{
	error::Error as StdError,
	fmt::{ Display, Formatter, Result as FmtResult },
	io::{ Error as IoError, ErrorKind as IoErrorKind }
};
pub use crate::{ plugin::{ Plugin, FormatUid }, ffi::{ CSlice, AsCSlice, AsCSliceMut } };


/// The error kind
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ErrorKind {
	/// A plugin could not initialize itself
	InitializationError,
	/// The provided buffer is too small and cannot be resized
	BufferError{ required_size: usize },
	/// An operation is not permitted (at least not without providing authentication data)
	PermissionDenied{ requires_authentication: bool },
	/// An authentication error occurred (e.g. bad PIN, password etc.); if the amount of retries
	/// left is `None`, this means that there is no limit
	AccessDenied{ retries_left: Option<u64> },
	/// An IO-error occurred
	IoError,
	/// Invalid data
	InvalidData,
	/// There is no valid key available to decrypt the data
	NoKeyAvailable,
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