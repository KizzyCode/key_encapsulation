use crate::{ Error, PluginErrorType };
use ::std::{ marker::PhantomData, slice, u64 };


/// Creates a string from a C-string
pub trait FromCStr {
	/// Creates a string from `c_str`; if `c_str` is not null-terminated, the entire slice is
	/// converted to a string
	///
	/// _Note: This function panics if the string is not UTF-8_
	fn from_c_str(c_str: &[u8]) -> Self;
}
impl FromCStr for String {
	fn from_c_str(c_str: &[u8]) -> Self {
		// Find first zero byte
		let len = c_str.iter()
			.position(|b| *b == 0x00)
			.unwrap_or(c_str.len());
		
		// Convert the bytes to a string
		String::from_utf8(c_str[..len].to_vec()).expect("Plugin API violation")
	}
}


/// An immutable `slice_t` representation
#[repr(C)]
pub struct CSlice<'a> {
	pub data: *const u8,
	pub len: usize,
	_lifetime: PhantomData<&'a[u8]>
}
impl<'a> CSlice<'a> {
	/// Creates a new `slice_t` over `slice`
	pub fn new(slice: &'a[u8]) -> Self {
		CSlice{ data: slice.as_ptr(), len: slice.len(), _lifetime: PhantomData }
	}
	
	/// Creates a slice from `self`
	pub unsafe fn as_slice(&self) -> &'a[u8] {
		slice::from_raw_parts(self.data, self.len)
	}
}


/// A mutable `slice_t` representation
#[repr(C)]
pub struct CSliceMut<'a> {
	pub data: *mut u8,
	pub len: usize,
	_lifetime: PhantomData<&'a mut[u8]>
}
impl<'a> CSliceMut<'a> {
	/// Creates a new `slice_t` over `slice`
	pub fn new(slice: &'a mut[u8]) -> Self {
		CSliceMut{ data: slice.as_mut_ptr(), len: slice.len(), _lifetime: PhantomData }
	}
}


/// Defines the error "numbers"
mod errno {
	pub const ENONE: [u8; 16] = *b"ENONE\0\0\0\0\0\0\0\0\0\0\0";
	pub const EINIT: [u8; 16] = *b"EINIT\0\0\0\0\0\0\0\0\0\0\0";
	pub const EPERM: [u8; 16] = *b"EPERM\0\0\0\0\0\0\0\0\0\0\0";
	pub const EACCESS: [u8; 16] = *b"EACCESS\0\0\0\0\0\0\0\0\0";
	pub const EIO: [u8; 16] = *b"EIO\0\0\0\0\0\0\0\0\0\0\0\0\0";
	pub const EILSEQ: [u8; 16] = *b"EILSEQ\0\0\0\0\0\0\0\0\0\0";
	pub const ENOKEY: [u8; 16] = *b"ENOKEY\0\0\0\0\0\0\0\0\0\0";
	pub const ECANCELED: [u8; 16] = *b"ECANCELED\0\0\0\0\0\0\0";
	pub const ETIMEDOUT: [u8; 16] = *b"ETIMEDOUT\0\0\0\0\0\0\0";
	pub const EINVAL: [u8; 16] = *b"EINVAL\0\0\0\0\0\0\0\0\0\0";
	pub const EOTHER: [u8; 16] = *b"EOTHER\0\0\0\0\0\0\0\0\0\0";
}


/// An `error_t` implementation
#[repr(C)] #[derive(Copy, Clone)]
pub struct CError {
	pub type_id: [u8; 16],
	
	pub file: [u8; 256],
	pub line: u32,
	pub description: [u8; 1024],
	
	pub info: u64
}
impl CError {
	/// Checks if the `CError` is an error and converts it accordingly
	pub fn check(self) -> Result<(), Error> {
		// Match the error type
		let error_type = match self.type_id {
			errno::ENONE => return Ok(()),
			errno::EINIT => PluginErrorType::EInit,
			errno::EPERM => PluginErrorType::EPerm{ requires_authentication: self.info != 0 },
			errno::EACCESS => PluginErrorType::EAccess {
				retries_left: match self.info {
					u64::MAX => None,
					retries_left => Some(retries_left)
				}
			},
			errno::EIO => PluginErrorType::EIO,
			errno::EILSEQ => PluginErrorType::EIlSeq,
			errno::ENOKEY => PluginErrorType::ENoKey,
			errno::ECANCELED => PluginErrorType::ECancelled,
			errno::ETIMEDOUT => PluginErrorType::ETimedOut,
			errno::EINVAL => PluginErrorType::EInval{ argument_index: self.info },
			errno::EOTHER => PluginErrorType::EOther{ code: self.info },
			_ => panic!("Plugin API violation")
		};
		
		// Convert strings
		Err(Error::PluginError{
			file: String::from_c_str(&self.file),
			line: self.line,
			description: String::from_c_str(&self.description),
			error_type
		})
	}
}