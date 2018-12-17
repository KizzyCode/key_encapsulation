//! This crate is an implementation of the KeyEncapsulation specification (see
//! "KeyEncapsulation.asciidoc")


/// Checks if `$condition` evaluates to `true` and returns `$error` if this is not the case
macro_rules! check {
    ($condition:expr, $error:expr) => (if !$condition {
    	return Err(::std::convert::From::from($error))
    });
}
// Import `asn1_der` explicitly to support the derive macro
#[macro_use] extern crate asn1_der;


mod plugin;
mod capsule;
mod pool;

use ::{
	asn1_der::Asn1DerError,
	std::{ ffi::NulError, io::{ Error as IoError, ErrorKind as IoErrorKind } }
};
pub use self::{ capsule::Capsule, pool::Pool };


/// A plugin error
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PluginError {
	/// The library could not be initialized
	InitializationError,
	/// The provided buffer is too small
	BufferIsTooSmall,
	/// An authentication error occurred (e.g. bad PIN, password etc.)
	AuthenticationError,
	/// The operation is not allowed
	OperationNotAllowed,
	/// An plugin internal I/O-error occurred
	IoError,
	/// The operation was canceled by the user
	OperationCanceled,
	/// The operation timed out (e.g. took longer than 90s)
	OperationTimedOut,
	/// Another (plugin specific) error occurred
	Other(u8)
}
impl PluginError {
	/// Checks `errno` and returns either nothing or the corresponding `PluginError`
	pub fn check_errno(errno: u8) -> Result<(), Self> {
		match errno {
			0 => Ok(()),
			1 => Err(PluginError::BufferIsTooSmall),
			2 => Err(PluginError::AuthenticationError),
			3 => Err(PluginError::OperationNotAllowed),
			4 => Err(PluginError::IoError),
			5 => Err(PluginError::OperationCanceled),
			6 => Err(PluginError::OperationTimedOut),
			other => Err(PluginError::Other(other))
		}
	}
}


/// The crate's error type
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
	/// A plugin error occurred
	PluginError(PluginError),
	/// A library related I/O-error occurred
	IoError(IoErrorKind),
	/// An invalid API-call was made (e.g. an invalid capsule format or capsule key ID was provided)
	ApiMisuse,
	/// Something is unsupported (e.g. the plugin's API version or the capsule format)
	Unsupported
}
impl From<PluginError> for Error {
	fn from(plugin_error: PluginError) -> Self {
		Error::PluginError(plugin_error)
	}
}
impl From<NulError> for Error {
	fn from(_: NulError) -> Self {
		Error::ApiMisuse
	}
}
impl From<IoErrorKind> for Error {
	fn from(io_error_kind: IoErrorKind) -> Self {
		Error::IoError(io_error_kind)
	}
}
impl From<IoError> for Error {
	fn from(io_error: IoError) -> Self {
		io_error.kind().into()
	}
}
impl From<Asn1DerError> for Error {
	fn from(_: Asn1DerError) -> Self {
		Error::IoError(IoErrorKind::InvalidData)
	}
}