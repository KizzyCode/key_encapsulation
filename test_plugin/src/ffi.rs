use ::std::{ slice, ptr, os::raw::c_void };


/// Creates and returns a new `CError`/`error_t`
#[macro_export]
macro_rules! err {
	($type_id:expr, $description:expr, $info:expr) => ({
		crate::ffi::CError::new($type_id, file!(), line!(), $description, $info)
	})
}
/// Creates and returns an `ENONE` `CError`/`error_t`
#[macro_export]
macro_rules! ok {
	() => ({
		err!(crate::ffi::errno::ENONE, "Nothing happened; everything is fine :)", 0)
	});
}


/// Defines the error "numbers"
#[allow(unused)]
pub mod errno {
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
	
	/// Checks if `self` is `ENONE`
	pub fn check(self) -> Result<(), Self> {
		match self.type_id {
			errno::ENONE => Ok(()),
			_ => Err(self)
		}
	}
}


/// A `slice_t` implementation
#[repr(C)]
pub struct CSlice {
	data: *mut u8,
	capacity: usize,
	len: usize,
	
	handle: *mut c_void,
	reallocate: Option<unsafe extern "C" fn(*mut Self, usize)>
}
impl CSlice {
	/// The payload as slice
	pub fn slice(&self) -> &[u8] {
		unsafe{ slice::from_raw_parts(self.data, self.len) }
	}
	/// Writes `data` to the slice (tries to reallocate if necessary)
	pub fn write(&mut self, data: &[u8]) -> Result<(), CError> {
		// Ensure the capacity
		if self.capacity < data.len() {
			let reallocate = self.reallocate
				.ok_or(err!(errno::ENOBUF, "Invalid buffer size", data.len() as u64))?;
			unsafe{ reallocate(self, data.len()) }
		}
		
		// Copy the data and adjust the length
		unsafe{ ptr::copy(data.as_ptr(), self.data, data.len()); }
		Ok(self.len = data.len())
	}
}