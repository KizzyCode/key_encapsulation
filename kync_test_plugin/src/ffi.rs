use ::std::{ slice, ptr, u64, os::raw::{ c_char, c_void } };


/// A `source_t` implementation
#[repr(C)]
pub struct CSource {
	data: Option<unsafe extern "C" fn(handle: *mut c_void, len: *mut usize) -> *const u8>,
	handle: *mut c_void
}
impl CSource {
	/// The available data or `None` if the source is unavailable
	pub fn data(&self) -> Option<&[u8]> {
		let mut len = 0usize;
		match unsafe{ (self.data.unwrap())(self.handle, &mut len) } {
			data if data.is_null() => None,
			data => Some(unsafe{ slice::from_raw_parts(data, len) })
		}
	}
}


/// A `sink_t` implementation
#[repr(C)]
pub struct CSink {
	data: Option<unsafe extern "C" fn(handle: *mut c_void, len: usize) -> *mut u8>,
	handle: *mut c_void
}
impl CSink {
	/// Requests a `len`-sized mutable slice to write some data to or `None` in case no more data
	/// can be written
	pub fn data(&mut self, len: usize) -> Option<&mut[u8]> {
		match unsafe{ (self.data.unwrap())(self.handle, len) } {
			data if data.is_null() => None,
			data => Some(unsafe{ slice::from_raw_parts_mut(data, len) })
		}
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
	/// Creates a new error with `t` as error type and `i` as info
	fn new(t: &'static [u8], i: u64) -> Self {
		// Ensure that the type is `'\0'`-terminated and create the error
		assert_eq!(t.last(), Some(&b'\0'));
		CError{ error_type: t.as_ptr() as *const c_char, description: ptr::null(), info: i }
	}
	/// Adds `d` as description to self
	pub fn desc(mut self, d: &'static [u8]) -> Self {
		// Ensure that the description is `'\0'`-terminated and set the description
		assert_eq!(d.last(), Some(&b'\0'));
		self.description = d.as_ptr() as *const c_char;
		self
	}
	
	/// Creates a new `CError` that signalizes that no error occurred
	pub fn ok() -> Self {
		CError{ error_type: ptr::null(), description: ptr::null(), info: 0 }
	}
	/// Creates an `EPERM` error
	pub fn eperm(required_authentication: bool) -> Self {
		Self::new(b"EPERM\0", if required_authentication { 1 } else { 0 })
	}
	/// Creates an `EACCES` error
	pub fn eacces(retries_left: Option<u64>) -> Self {
		Self::new(b"EACCES\0", retries_left.unwrap_or(u64::MAX))
	}
	/// Creates an `ENOBUF` error
	pub fn enobuf(required_size: u64) -> Self {
		Self::new(b"ENOBUF\0", required_size)
	}
	/// Creates an `EIO` error
	pub fn eio() -> Self {
		Self::new(b"EIO\0", 0)
	}
	/// Creates an `EILSEQ` error
	pub fn eilseq() -> Self {
		Self::new(b"EILSEQ\0", 0)
	}
	/// Creates an `ENOKEY` error
	pub fn enokey() -> Self {
		Self::new(b"ENOKEY\0", 0)
	}
	/// Creates an `EINVAL` error
	pub fn einval(index: u64) -> Self {
		Self::new(b"EINVAL\0", index)
	}
	/// Creates an `ECANCELED` error
	pub fn ecanceled() -> Self {
		Self::new(b"ECANCELED\0", 0)
	}
	/// Creates an `ETIMEDOUT` error
	pub fn etimedout() -> Self {
		Self::new(b"ETIMEDOUT\0", 0)
	}
	/// Creates an `EOTHER` error
	pub fn eother(errno: u64) -> Self {
		Self::new(b"EOTHER\0", errno)
	}
}