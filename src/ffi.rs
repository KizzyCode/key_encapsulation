use crate::{ KyncError, ErrorKind };
use std::{ ptr, slice, usize, u64, marker::PhantomData, os::raw::{ c_char, c_void } };


/// A `source_t` implementation
#[repr(C)]
pub struct CSource<'a> {
	data: unsafe extern "C" fn(handle: *mut c_void, len: *mut usize) -> *const u8,
	handle: *mut c_void,
	_lifetime: PhantomData<&'a[u8]>
}
/// A trait for creating a `CSource` over an element
pub trait AsCSource<'a> {
	/// Returns a `CSource` over `self`
	fn as_c_source(&'a self) -> CSource<'a>;
}
impl<'a> AsCSource<'a> for &'a[u8] {
	fn as_c_source(&self) -> CSource {
		// Type-specific `data` implementation
		unsafe extern "C" fn data(handle: *mut c_void, len: *mut usize) -> *const u8
		{
			// Cast handle to `T` and then to `&[u8]`
			let handle = (handle as *const &[u8]).as_ref().unwrap();
			
			// Adjust `len` and return the pointer over `handle`
			*len.as_mut().unwrap() = handle.len();
			handle.as_ptr()
		}
		
		CSource{ data, handle: self as *const &[u8] as *mut c_void, _lifetime: PhantomData }
	}
}
impl<'a> AsCSource<'a> for Option<&'a[u8]> {
	fn as_c_source(&self) -> CSource {
		// None-specific `data` implementation
		unsafe extern "C" fn data_none(_handle: *mut c_void, _len: *mut usize) -> *const u8 {
			ptr::null()
		}
		
		// Check if we have a slice or not
		match self {
			Some(slice) => slice.as_c_source(),
			None => CSource{ data: data_none, handle: ptr::null_mut(), _lifetime: PhantomData }
		}
	}
}


/// A `sink_t` implementation
#[repr(C)]
pub struct CSink<'a> {
	data: unsafe extern "C" fn(handle: *mut c_void, len: usize) -> *mut u8,
	handle: *mut c_void,
	_lifetime: PhantomData<&'a mut Vec<u8>>
}
/// A trait for creating a `CSink` with an element
pub trait AsCSink {
	/// Creates a `CSink` with `self` as backing
	fn as_c_sink(&mut self) -> CSink;
}
impl AsCSink for Vec<u8> {
	fn as_c_sink(&mut self) -> CSink {
		// `data` implementation
		unsafe extern "C" fn data(handle: *mut c_void, len: usize) -> *mut u8 {
			// Cast handle to the vector
			let handle = (handle as *mut Vec<u8>).as_mut().unwrap();
			
			// Resize handle and return the pointer over the appended data
			let offset = handle.len();
			handle.resize(offset + len, 0);
			handle.as_mut_ptr().add(offset)
		}
		
		CSink{ data, handle: self as *mut Vec<u8> as *mut c_void, _lifetime: PhantomData }
	}
}


/// Creates a string from a `'\0'`-terminated C-string
pub trait FromCStr: Sized {
	/// Creates a string from a `c_str`; reads until a `'\0`-byte is found and returns
	/// `(string, string_len)` or `None` if `c_str` is `NULL`.
	///
	/// _Note: This function panics if the string is not UTF-8_
	unsafe fn from_c_str(c_str: *const c_char) -> Option<(Self, usize)>;
	
	/// Creates a string from a `c_str`; reads until a `'\0`-byte is found and returns
	/// `(string, string_len)` or `None` if no terminating `'\0'`-byte was found.
	///
	/// _Note: This function panics if the string is not UTF-8_
	fn from_c_str_slice(c_str: &[u8]) -> Option<(Self, usize)>;
}
impl FromCStr for String {
	unsafe fn from_c_str(c_str: *const c_char) -> Option<(Self, usize)> {
		// Cast pointer
		let c_str = match c_str.is_null() {
			true => return None,
			false => c_str as *const u8
		};
		
		// Determine the string length
		let mut len = 0usize;
		while c_str.add(len).read() != 0x00 { len += 1 }
		
		// Create vector and string
		let c_str = slice::from_raw_parts(c_str as *const u8, len).to_vec();
		Some((String::from_utf8(c_str).unwrap(), len))
	}
	
	fn from_c_str_slice(c_str: &[u8]) -> Option<(Self, usize)> {
		// Determine the string length and create the string
		let len = c_str.iter().enumerate()
			.find_map(|(i, b)| if *b == b'\0' { Some(i) } else { None })?;
		Some((String::from_utf8(c_str[..len].to_vec()).unwrap(), len))
	}
}


/// An `error_t` implementation
#[repr(C)] #[derive(Copy, Clone)]
pub struct CError {
	error_type: *const c_char,
	description: *const c_char,
	info: u64
}
impl CError {
	/// Checks if the `CError` is an error and converts it accordingly
	pub fn check(self) -> Result<(), KyncError> {
		// Check if there is an error and if so convert the error type to a string
		let error_type = match unsafe{ String::from_c_str(self.error_type) } {
			Some(error_type) => error_type,
			None => return Ok(())
		};
		
		// Match the error type
		let kind = match error_type.0.as_str() {
			"EPERM" => ErrorKind::PermissionDenied{ requires_authentication: self.info != 0 },
			"EACCESS" => ErrorKind::AccessDenied {
				retries_left: match self.info {
					u64::MAX => None,
					retries_left => Some(retries_left)
				}
			},
			"ENOBUF" => ErrorKind::BufferError { required_size: self.info },
			"EIO" => ErrorKind::IoError,
			"EILSEQ" => ErrorKind::InvalidData,
			"ENOKEY" => ErrorKind::NoKeyAvailable,
			"EINVAL" => ErrorKind::InvalidParameter{ index: self.info },
			"ECANCELED" => ErrorKind::OperationCancelled,
			"ETIMEDOUT" => ErrorKind::OperationTimedOut,
			"EOTHER" => ErrorKind::OtherPluginError{ errno: self.info },
			_ => unreachable!("Invalid error type")
		};
		
		// Convert strings
		Err(KyncError {
			kind,
			desc: unsafe{ String::from_c_str(self.description) }.map(|s| s.0)
		})
	}
}