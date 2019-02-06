use crate::{ Error, ErrorKind };
use std::{ marker::PhantomData, slice, usize, u64, cmp::min, ptr, os::raw::c_void };


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


/// A trait for types that are convertible to a `CSlice<*const u8>`
pub trait AsCSlice {
	fn c_slice<'a>(&'a self) -> CSlice<'a, *const u8>;
}
/// A trait for types that are convertible to a `CSlice<*mut u8>`
pub trait AsCSliceMut {
	fn c_slice<'a>(&'a mut self) -> CSlice<'a, *mut u8>;
}


/// A `slice_t` implementation
///
/// This type is a C-ffi compatible struct over a slice, mutable slice or a mutable vector
///
/// _Warning: If the `CSlice` is passed as a mutable pointer, the `len`-field may get adjusted so
/// that the underlying backing may be larger than the amount of meaningful bytes in `self`. To only
/// get the payload, either use `slice()` or get the payload's length using `len()`._
#[repr(C)]
pub struct CSlice<'a, T> {
	data: T,
	capacity: usize,
	len: usize,
	
	handle: *mut c_void,
	reallocate: Option<unsafe extern "C" fn(*mut Self, usize)>,
	_lifetime: PhantomData<&'a mut ()>
}
impl<'a> CSlice<'a, *mut u8> {
	/// The length of the meaningful bytes
	pub fn len(&self) -> usize {
		self.len
	}
	/// The payload as slice
	pub fn slice(&self) -> &[u8] {
		unsafe{ slice::from_raw_parts(self.data, self.len) }
	}
}
impl AsCSlice for &[u8] {
	fn c_slice<'a>(&'a self) -> CSlice<'a, *const u8> {
		CSlice {
			data: self.as_ptr(),
			capacity: self.len(),
			len: self.len(),
			
			handle: ptr::null_mut(),
			reallocate: None,
			_lifetime: PhantomData
		}
	}
}
impl AsCSliceMut for &mut[u8] {
	fn c_slice<'a>(&'a mut self) -> CSlice<'a, *mut u8> {
		CSlice {
			data: self.as_mut_ptr(),
			capacity: self.len(),
			len: self.len(),
			
			handle: ptr::null_mut(),
			reallocate: None,
			_lifetime: PhantomData
		}
	}
}
impl AsCSliceMut for &mut Vec<u8> {
	fn c_slice<'a>(&'a mut self) -> CSlice<'a, *mut u8> {
		/// The reallocation function for a vector
		unsafe extern "C" fn reallocate(slice: *mut CSlice<*mut u8>, new_size: usize) {
			// Extract pointers
			let slice = slice.as_mut().unwrap();
			let vec = (slice.handle as *mut Vec<u8>).as_mut().unwrap();
			
			// Resize vec and readjust slice fields
			vec.resize(new_size, 0);
			slice.data = vec.as_mut_ptr();
			slice.capacity = vec.len();
			slice.len = min(slice.len, vec.len())
		}
		
		// Create the `CSlice`
		CSlice {
			data: self.as_mut_ptr(),
			capacity: self.len(),
			len: self.len(),
			
			handle: (*self as *mut Vec<u8>) as *mut c_void,
			reallocate: Some(reallocate),
			_lifetime: PhantomData
		}
	}
}


/// Defines the error "numbers"
mod errno {
	pub const ENONE: [u8; 16] = *b"ENONE\0\0\0\0\0\0\0\0\0\0\0";
	pub const EINIT: [u8; 16] = *b"EINIT\0\0\0\0\0\0\0\0\0\0\0";
	pub const ENOBUF: [u8; 16] = *b"ENOBUF\0\0\0\0\0\0\0\0\0\0";
	pub const EPERM: [u8; 16] = *b"EPERM\0\0\0\0\0\0\0\0\0\0\0";
	pub const EACCESS: [u8; 16] = *b"EACCESS\0\0\0\0\0\0\0\0\0";
	pub const EIO: [u8; 16] = *b"EIO\0\0\0\0\0\0\0\0\0\0\0\0\0";
	pub const EILSEQ: [u8; 16] = *b"EILSEQ\0\0\0\0\0\0\0\0\0\0";
	pub const ENOKEY: [u8; 16] = *b"ENOKEY\0\0\0\0\0\0\0\0\0\0";
	pub const ECANCELED: [u8; 16] = *b"ECANCELED\0\0\0\0\0\0\0";
	pub const ETIMEDOUT: [u8; 16] = *b"ETIMEDOUT\0\0\0\0\0\0\0";
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
		let kind = match self.type_id {
			errno::ENONE => return Ok(()),
			
			errno::EINIT => ErrorKind::InitializationError,
			errno::ENOBUF => ErrorKind::BufferError {
				required_size: match self.info {
					s if s < usize::MAX as u64 => s as usize,
					_ => panic!("Plugin API violation")
				}
			},
			errno::EPERM => ErrorKind::PermissionDenied{ requires_authentication: self.info != 0 },
			errno::EACCESS => ErrorKind::AccessDenied {
				retries_left: match self.info {
					u64::MAX => None,
					retries_left => Some(retries_left)
				}
			},
			errno::EIO => ErrorKind::IoError,
			errno::EILSEQ => ErrorKind::InvalidData,
			errno::ENOKEY => ErrorKind::NoKeyAvailable,
			errno::ECANCELED => ErrorKind::OperationCancelled,
			errno::ETIMEDOUT => ErrorKind::OperationTimedOut,
			errno::EOTHER => ErrorKind::OtherPluginError{ errno: self.info },
			_ => panic!("Plugin API violation")
		};
		
		// Convert strings
		Err(Error {
			kind, desc: Some(format!(
				"Plugin error: {} @{}:{}",
				String::from_c_str(&self.description),
				String::from_c_str(&self.file), self.line
			))
		})
	}
}