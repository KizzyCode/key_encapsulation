#![allow(non_camel_case_types)]
use crate::{ KyncError, KyncErrorKind };
use std::{
	ptr, slice, ffi::CStr, marker::PhantomData,
	os::raw::{ c_char, c_void }
};


/// An extension to work with statically allocated constant C strings
pub trait StaticCharPtrExt {
	/// Checks if there is an non-`NULL` error pointer
	fn check(self, kind: KyncErrorKind) -> Result<(), KyncError>;
}
impl StaticCharPtrExt for *const c_char {
	fn check(self, k: KyncErrorKind) -> Result<(), KyncError> {
		match self.is_null() {
			true => Ok(()),
			false => Err(KyncError(k, unsafe{ CStr::from_ptr(self) }))
		}
	}
}


/// The sys bindings
pub mod sys {
	include!("sys.rs");
}


/// An idiomatic wrapper around `sys::slice_t`
pub struct Slice<'a>(sys::slice_t, PhantomData<&'a[u8]>);
impl<'a> Slice<'a> {
	/// A pointer to the underlying `sys::slice_t`
	pub fn slice_t(&self) -> &sys::slice_t {
		&self.0
	}
}
impl<'a> From<&'a[u8]> for Slice<'a> {
	fn from(s: &'a[u8]) -> Self {
		Self(sys::slice_t{ ptr: s.as_ptr(), len: s.len() }, PhantomData)
	}
}


/// An idiomatic wrapper around `sys::write_t`
pub struct Writer(sys::write_t);
impl Writer {
	/// Creates a new empty writer
	pub fn new() -> Self {
		let handle = Box::new(vec![vec![0u8; 0]; 0]);
		Self(sys::write_t{ handle: Box::into_raw(handle).cast(), write: Some(Self::write) })
	}
	/// A pointer to the underlying `sys::write_t`
	pub fn write_t(&mut self) -> &mut sys::write_t {
		&mut self.0
	}
	
	/// The write implementation
	extern "C" fn write(handle: *mut c_void, data: *const sys::slice_t) -> *const c_char {
		// Cast and deref the pointers
		let handle = unsafe{ handle.cast::<Vec<Vec<u8>>>().as_mut() }
			.expect("Unexpected NULL pointer");
		let data = unsafe{ data.as_ref() }
			.expect("Unexpected NULL pointer");
		
		// Append the slice
		let data = unsafe{ slice::from_raw_parts(data.ptr, data.len) };
		handle.push(data.to_vec());
		ptr::null()
	}
}
impl From<Writer> for Vec<Vec<u8>> {
	fn from(writer: Writer) -> Self {
		assert!(!writer.0.handle.is_null(), "Unexpected NULL pointer");
		assert!(writer.0.write == Some(Writer::write), "Incompatible implementation");
		*unsafe{ Box::from_raw(writer.0.handle.cast::<Vec<Vec<u8>>>()) }
	}
}
impl From<Writer> for Vec<u8> {
	fn from(writer: Writer) -> Self {
		let vecs: Vec<Vec<u8>> = writer.into();
		vecs.into_iter().flatten().collect()
	}
}