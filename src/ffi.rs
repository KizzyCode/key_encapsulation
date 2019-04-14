use crate::{ KyncError, ErrorKind };
use std::{ slice, usize, u64 };


/// A trait to extend `*const error_t`
pub trait ErrorExt {
	/// Checks if `self` points to an `error_t` and translates it to a `Result<(), KyncError>`
	fn check(self) -> Result<(), KyncError>;
}
impl ErrorExt for *const error_t {
	//noinspection RsMatchCheck
	fn check(self) -> Result<(), KyncError> {
		// Check if the pointer contains an error or is `NULL`
		let error = match unsafe{ self.as_ref() } {
			Some(error) => error,
			None => return Ok(())
		};
		
		// Get the error type and the description
		let error_type = match error.error_type_len {
			0 => panic!("Invalid error type"),
			len => unsafe{ slice::from_raw_parts(error.error_type, len) }
		};
		let desc = match error.description_len {
			0 => None,
			len => Some(unsafe{ slice::from_raw_parts(error.description, len) })
		};
		
		// Match the error type
		let kind = match error_type {
			b"EPERM" => ErrorKind::PermissionDenied{ requires_authentication: error.info != 0 },
			b"EACCESS" => ErrorKind::AccessDenied {
				retries_left: match error.info {
					u64::MAX => None,
					retries_left => Some(retries_left)
				}
			},
			b"EIO" => ErrorKind::IoError,
			b"EILSEQ" => ErrorKind::InvalidData,
			b"ENOTFOUND" => ErrorKind::ItemNotFound,
			b"EINVAL" => ErrorKind::InvalidParameter{ index: error.info },
			b"ECANCELED" => ErrorKind::OperationCancelled,
			b"ETIMEDOUT" => ErrorKind::OperationTimedOut,
			b"EOTHER" => ErrorKind::OtherPluginError{ errno: error.info },
			_ => unreachable!("Invalid error type")
		};
		
		// Create the error
		Err(KyncError{ kind, desc: desc.map(|v| String::from_utf8_lossy(v).to_string()) })
	}
}


/// The type of a thread-local error
#[repr(C)] #[allow(non_camel_case_types)]
pub struct error_t {
	/// The error type (one of the predefined identifiers) or empty in case no error occurred (yet)
	pub error_type: *const u8,
	pub error_type_len: usize,
	/// The error description or empty
	pub description: *const u8,
	pub description_len: usize,
	/// Some error specific info
	pub info: u64
}


/// Initializes the plugin
///
/// - `api_version`: A pointer to an integer to write the plugin\'s API version to
/// - `log_level`: The log level the plugin should use (only applies to stderr)
pub type InitFn = unsafe extern "C" fn(api_version: *mut u8, log_level: u8);


/// Computes the buffer size necessary for a call to `func` which will process `input_len` bytes of
/// input and writes the result to `buf_len`
///
///  - `buf_len`: A pointer to an integer to write the computed buffer length to
///  - `fn_name`: The function identifier
///  - `fn_name_len`: The length of `fn_name`
///  - `input_len`: The amount of input bytes the function will process
pub type BufLenFn = unsafe extern "C" fn(
	buf_len: *mut usize,
	fn_name: *const u8, fn_name_len: usize,
	input_len: usize
);


/// Makes `uid` point to the capsule format UID
///
/// - `uid`: A pointer to a pointer to write the address of the static UID constant to
/// - `uid_written`: A pointer to an integer to reflect the amount of bytes written to `uid`
pub type CapsuleFormatUidFn = unsafe extern "C" fn (uid: *mut u8, uid_written: *mut usize);


/// Writes all crypto item IDs as `\\0`-terminated, concatenated UTF-8 strings to `buf`
///
///  - `buf`: The buffer to write the concatenated crypto item UIDs to
///  - `buf_written`: A pointer to an integer to reflect the amount of bytes written to `buf`
///
/// Returns either `NULL` in case of success or a pointer to the thread-local error struct
pub type CryptoItemIdsFn = unsafe extern "C" fn(buf: *mut u8, buf_written: *mut usize)
	-> *const error_t;


/// Seals `key` into `buf`
///
///  - `buf`: The buffer to write the sealed key to
///  - `buf_written`: A pointer to an integer to reflect the amount of bytes written to `buf`
///  - `key`: The key to seal
///  - `key_len`: The length of `key`
///  - `crypto_item_id`: The crypt item to use (may be `NULL`; see specification)
///  - `crypto_item_id_len`: The length of `crypto_item_uid`
///  - `user_secret`: The user secret to use (may be `NULL`; see specification)
///  - `user_secret_len`: The length of `user_secret`
///
/// Returns either `NULL` in case of success or a pointer to the thread-local error struct
pub type SealFn = unsafe extern "C" fn(
	buf: *mut u8, buf_written: *mut usize,
	key: *const u8, key_len: usize,
	crypto_item_id: *const u8, crypto_item_id_len: usize,
	user_secret: *const u8, user_secret_len: usize
) -> *const error_t;

/// Opens `capsule` into `buf`
///
///  - `buf`: The buffer to write the opened key to
///  - `buf_written`: A pointer to an integer to reflect the amount of bytes written to `buf`
///  - `capsule`: The capsule to open
///  - `capsule_len`: The length of `capsule`
///  - `user_secret`: The user secret to use (may be `NULL`; see specification)
///  - `user_secret_len`: The length of `user_secret`
///
/// Returns either `NULL` in case of success or a pointer to the thread-local error struct
pub type OpenFn = unsafe extern "C" fn(
	buf: *mut u8, buf_written: *mut usize,
	capsule: *const u8, capsule_len: usize,
	user_secret: *const u8, user_secret_len: usize
) -> *const error_t;