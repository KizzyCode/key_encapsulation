mod error;

pub use self::error::*;
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