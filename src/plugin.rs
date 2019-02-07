use crate::{KyncError, ffi::{ CSlice, AsCSlice, AsCSliceMut, CError } };
use std::{ ptr, path::Path, fmt::{ Formatter, Debug, Result as FmtResult } };
use libloading::Library;


/// The current API version
const API_VERSION: u8 = 1;


/// A wrapper around the `64`-byte format UID
#[derive(Copy, Clone)]
pub struct FormatUid(pub [u8; 64]);
impl PartialEq for FormatUid {
	fn eq(&self, other: &Self) -> bool {
		self.0.as_ref() == other.0.as_ref()
	}
}
impl<T: AsRef<[u8]>> PartialEq<T> for FormatUid {
	fn eq(&self, other: &T) -> bool {
		self.0.as_ref() == other.as_ref()
	}
}
impl Debug for FormatUid {
	fn fmt(&self, f: &mut Formatter) -> FmtResult {
		write!(f, "FormatUid({})", String::from_utf8_lossy(self.0.as_ref()))
	}
}


/// A key capsule plugin (see "Kync.asciidoc" for further API documentation)
pub struct Plugin {
	capsule_format_uid: unsafe extern fn() -> [u8; 64],
	
	capsule_key_ids: unsafe extern fn(id_buffer: *mut CSlice<*mut u8>) -> CError,
	seal: unsafe extern fn(
		payload: *mut CSlice<*mut u8>, key_to_seal: *const CSlice<*const u8>,
		capsule_key_id: *const CSlice<*const u8>, user_secret: *const CSlice<*const u8>
	) -> CError,
	open: unsafe extern fn(
		key: *mut CSlice<*mut u8>, payload: *const CSlice<*const u8>,
		user_secret: *const CSlice<*const u8>
	) -> CError,
	
	_library: Library
}
impl Plugin {
	/// Load the library
	pub fn load(path: impl AsRef<Path>) -> Result<Self, KyncError> {
		// Determine the log-level
		let log_level = match cfg!(debug_assertions) {
			true => 1u8,
			false => 0u8
		};
		
		// Load library
		#[cfg(target_os = "linux")]
		let library: Library = {
			// Load library with RTLD_NOW | RTLD_NODELETE to fix a SIGSEGV
			// (see https://github.com/nagisa/rust_libloading/issues/41)
			::libloading::os::unix::Library::open(Some(path.as_ref()), 0x2 | 0x1000)?.into()
		};
		#[cfg(not(target_os = "linux"))]
		let library = Library::new(path.as_ref())?;
		
		// Validate loaded library
		unsafe {
			// Initialize library and check the API version
			let init =
				*library.get::<unsafe extern fn(u8, u8) -> CError>(b"init\0")?;
			init(API_VERSION, log_level).check()?;
		}
		
		// Create plugin
		Ok(Self {
			capsule_format_uid: *unsafe{ library.get(b"capsule_format_uid\0")? },
			
			capsule_key_ids: *unsafe{ library.get(b"capsule_key_ids\0")? },
			seal: *unsafe{ library.get(b"seal\0")? },
			open: *unsafe{ library.get(b"open\0")? },
			
			_library: library
		})
	}
	
	/// The capsule format UID
	pub fn capsule_format_uid(&self) -> FormatUid {
		FormatUid(unsafe{ (self.capsule_format_uid)() })
	}
	
	/// The available capsule keys
	pub fn capsule_key_ids(&self, mut buf: impl AsCSliceMut) -> Result<usize, KyncError> {
		let mut buf = buf.c_slice();
		unsafe{ (self.capsule_key_ids)(&mut buf) }.check()?;
		Ok(buf.len())
	}
	
	/// Seals a key into `der_payload` and returns the `der_payload` length
	pub fn seal(&self, mut buf: impl AsCSliceMut, key_to_seal: impl AsCSlice,
		capsule_key_id: Option<impl AsCSlice>, user_secret: Option<impl AsCSlice>)
		-> Result<usize, KyncError>
	{
		// Create buffer and readers
		let mut buf = buf.c_slice();
		
		let mut capsule_key_id =
			capsule_key_id.as_ref().map(|i| i.c_slice());
		let mut user_secret =
			user_secret.as_ref().map(|s| s.c_slice());
		
		// Map optionals to pointers
		let capsule_key_id=
			capsule_key_id.as_mut().map(|i| i as _)
				.unwrap_or(ptr::null_mut());
		let user_secret =
			user_secret.as_mut().map(|s| s as _)
				.unwrap_or(ptr::null_mut());
		
		// Call function
		unsafe{ (self.seal)(&mut buf, &key_to_seal.c_slice(), capsule_key_id, user_secret) }
			.check()?;
		Ok(buf.len())
	}
	
	/// Opens the capsule into `key` and returns the `key` length
	pub fn open(&self, mut buf: impl AsCSliceMut, payload: impl AsCSlice,
		user_secret: Option<impl AsCSlice>) -> Result<usize, KyncError>
	{
		// Create `slice_t`s
		let mut buf = buf.c_slice();
		
		let mut user_secret =
			user_secret.as_ref().map(|s| s.c_slice());
		
		// Map optionals to pointers
		let user_secret =
			user_secret.as_mut().map(|s| s as _)
				.unwrap_or(ptr::null_mut());
		
		// Call function
		unsafe{ (self.open)(&mut buf, &payload.c_slice(), user_secret) }.check()?;
		Ok(buf.len())
	}
}