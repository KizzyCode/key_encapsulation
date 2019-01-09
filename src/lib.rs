//! This crate is an implementation of the Kync specification (see "Kync.asciidoc")


/// Checks if `$condition` evaluates to `true` and returns `$error` if this is not the case
macro_rules! check {
	($condition:expr, $error:expr) => (if !$condition {
		return Err(::std::convert::From::from($error))
	});
}
// Import `asn1_der` explicitly to support the derive macro
#[macro_use] extern crate asn1_der;


mod ffi;
mod plugin;
mod capsule;
mod pool;

use ::{ asn1_der::Asn1DerError, std::io::{ Error as IoError, ErrorKind as IoErrorKind } };
pub use self::{ capsule::Capsule, pool::Pool };


/// A plugin error
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PluginErrorType {
	/// The library could not be initialized
	EInit,
	///
	EPerm{ requires_authentication: bool },
	/// An authentication error occurred (e.g. bad PIN, password etc.)
	EAccess{ retries_left: Option<u64> },
	/// An plugin internal I/O-error occurred
	EIO,
	/// Invalid data in key capsule
	EIlSeq,
	/// There is no valid key available to decrypt the data
	ENoKey,
	/// The operation was canceled by the user
	ECancelled,
	/// The operation timed out (e.g. took longer than 90s)
	ETimedOut,
	/// A plugin-related API error
	EInval{ argument_index: u64 },
	/// Another (plugin specific) error occurred
	EOther{ code: u64 }
}


/// The crate's error type
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Error {
	/// A plugin error occurred
	PluginError{ file: String, line: u32, description: String, error_type: PluginErrorType },
	/// A library related I/O-error occurred
	IoError(IoErrorKind),
	/// An invalid API-call was made (e.g. an invalid capsule format or capsule key ID was provided)
	ApiMisuse,
	/// Something is unsupported (e.g. the plugin's API version or the capsule format)
	Unsupported
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