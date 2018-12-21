macro_rules! check {
	($condition:expr, $error:expr) => (if !$condition { return $error.to_errno() });
}

mod ffi_tools;
pub mod key_capsule;


/// A plugin error
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
	/// The library could not be initialized
	InitializationError,
	/// An authentication error occurred (e.g. bad PIN, password etc.)
	AuthenticationError,
	/// The operation is not allowed
	OperationNotAllowed,
	/// An plugin internal I/O-error occurred
	IoError,
	/// Invalid data in plugin payload
	InvalidData,
	/// There is no valid key available to decrypt the data
	NoValidKey,
	/// The operation was canceled by the user
	OperationCanceled,
	/// The operation timed out (e.g. took longer than 90s)
	OperationTimedOut,
	/// A plugin-related API error
	ApiMisuse,
	/// Another (plugin specific) error occurred
	Other(u8)
}
impl Error {
	/// Converts the `PluginError` to the corresponding `errno`
	pub fn to_errno(self) -> u8 {
		match self {
			Error::InitializationError => 1,
			Error::AuthenticationError => 2,
			Error::OperationNotAllowed => 3,
			Error::IoError             => 4,
			Error::InvalidData         => 5,
			Error::NoValidKey          => 6,
			Error::OperationCanceled   => 7,
			Error::OperationTimedOut   => 8,
			Error::ApiMisuse           => 9,
			Error::Other(errno)        => errno
		}
	}
}
