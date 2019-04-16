//! This crate is an implementation of the KyNc specification (see
//! [Kync.asciidoc](https://github.com/KizzyCode/kync/blob/master/Kync.asciidoc))

mod ffi;

/// A key capsule plugin (see "Kync.asciidoc" for further API documentation) and some helpers
pub mod plugin;

use std::{
	io, error::Error,
	fmt::{ self, Display, Formatter }
};
pub use crate::plugin::Plugin;


/// The error kind
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ErrorKind {
	/// An operation is not permitted (at least not without providing authentication data)
	PermissionDenied{ requires_authentication: bool },
	/// An authentication error occurred (e.g. bad PIN, password etc.); if the amount of retries
	/// left is `None`, this means that there is no limit
	AccessDenied{ retries_left: Option<u64> },
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
	fn fmt(&self, f: &mut Formatter) -> fmt::Result {
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
impl From<io::ErrorKind> for KyncError {
	fn from(io_error_kind: io::ErrorKind) -> Self {
		Self{ kind: ErrorKind::IoError, desc: Some(format!("{:#?}", io_error_kind)) }
	}
}
impl From<io::Error> for KyncError {
	fn from(io_error: io::Error) -> Self {
		Self{ kind: ErrorKind::IoError, desc: Some(format!("{}", io_error)) }
	}
}
impl Error for KyncError {}