use ::std::{ marker::PhantomData, slice };


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
		String::from_utf8(c_str[..len].to_vec()).unwrap()
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
	
	/// Creates a mutable slice from `self`
	pub unsafe fn as_slice_mut(&mut self) -> &'a mut[u8] {
		slice::from_raw_parts_mut(self.data, self.len)
	}
}


/// Defines the error "numbers"
#[allow(unused)]
pub mod errno {
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
	/// Creates a new `error_t`
	pub fn new(type_id: [u8; 16], file: impl AsRef<str>, line: u32, description: impl AsRef<str>,
		info: u64) -> Self
	{
		macro_rules! str_to_array {
			($str:expr => [$len:expr]) => ({
				assert!($str.len() <= $len, "`$str` does not fit into the array");
				
				let mut array: [u8; $len] = [0; $len];
				array[..$str.len()].copy_from_slice($str.as_bytes());
				array
			});
		}
		
		CError {
			type_id,
			file: str_to_array!(file.as_ref() => [256]), line,
			description: str_to_array!(description.as_ref() => [1024]),
			info
		}
	}
}


/// Creates and returns a new `CError`/`error_t`
#[macro_export]
macro_rules! err {
	($type_id:expr, $description:expr, $info:expr) => ({
		return crate::ffi::CError::new($type_id, file!(), line!(), $description, $info)
	})
}
/// Creates and returns an `ENONE` `CError`/`error_t`
#[macro_export]
macro_rules! ok {
	() => ({
		err!(crate::ffi::errno::ENONE, "Nothing happened; everything is fine :)", 0)
	});
}