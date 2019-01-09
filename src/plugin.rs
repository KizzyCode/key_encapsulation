use crate::{ Error, ffi::{ CSlice, CSliceMut, CError } };
use ::{ libloading::Library, std::{ ptr, path::Path } };


const API_VERSION: u8 = 1;


/// A key capsule plugin (see "Kync.asciidoc" for further API documentation)
pub struct Plugin {
	capsule_format_uid: unsafe extern fn() -> CSlice<'static>,
	buf_len_max: unsafe extern fn(fn_name: *const CSlice) -> usize,
	
	capsule_key_ids: unsafe extern fn(id_buffer: *mut CSliceMut) -> CError,
	seal: unsafe extern fn(
		der_tag: *mut u8, der_payload: *mut CSliceMut,
		key_to_seal: *const CSlice,
		capsule_key_id: *const CSlice, user_secret: *const CSlice
	) -> CError,
	open: unsafe extern fn(
		key: *mut CSliceMut,
		der_tag: u8, der_payload: *const CSlice,
		user_secret: *const CSlice
	) -> CError,
	
	_library: Library
}
impl Plugin {
	/// Load the library
	pub fn load(path: impl AsRef<Path>) -> Result<Self, Error> {
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
			buf_len_max: *unsafe{ library.get(b"buf_len_max\0")? },
			
			capsule_key_ids: *unsafe{ library.get(b"capsule_key_ids\0")? },
			seal: *unsafe{ library.get(b"seal\0")? },
			open: *unsafe{ library.get(b"open\0")? },
			
			_library: library
		})
	}
	
	/// The capsule format UID
	pub fn capsule_format_uid(&self) -> &[u8] {
		unsafe{ (self.capsule_format_uid)().as_slice() }
	}
	
	/// The _maximum_ length a buffer needs to store all data produced by a function
	pub fn buf_len_max(&self, fn_name: &str) -> usize {
		unsafe{ (self.buf_len_max)(&CSlice::new(fn_name.as_bytes())) }
	}
	
	/// Writes the available capsule key IDs into `buf` and returns the new buffer size
	pub fn capsule_key_ids(&self, buf: &mut[u8]) -> Result<usize, Error> {
		let mut buf = CSliceMut::new(buf);
		unsafe{ (self.capsule_key_ids)(&mut buf) }.check()?;
		Ok(buf.len)
	}
	
	/// Seals a key into `der_payload` and returns the `der_payload` length
	pub fn seal(&self, der_tag: &mut u8, der_payload: &mut[u8], key_to_seal: &[u8],
		capsule_key_id: Option<&str>, user_secret: Option<&[u8]>) -> Result<usize, Error>
	{
		// Create `slice_t`s
		let mut der_payload = CSliceMut::new(der_payload);
		let key_to_seal = CSlice::new(key_to_seal);
		
		let capsule_key_id =
			capsule_key_id.map(|i| CSlice::new(i.as_bytes()));
		let user_secret = user_secret.map(|s| CSlice::new(s));
		
		// Map optionals to pointers
		let capsule_key_id: *const CSlice = capsule_key_id.as_ref().map(|i| i as _)
			.unwrap_or(ptr::null());
		let user_secret: *const CSlice = user_secret.as_ref().map(|s| s as _)
			.unwrap_or(ptr::null());
		
		// Call function
		unsafe{ (self.seal)(
			der_tag, &mut der_payload,
			&key_to_seal, capsule_key_id, user_secret
		) }.check()?;
		Ok(der_payload.len)
	}
	
	/// Opens the capsule into `key` and returns the `key` length
	pub fn open(&self, key: &mut[u8], der_tag: u8, der_payload: &[u8], user_secret: Option<&[u8]>)
		-> Result<usize, Error>
	{
		// Create `slice_t`s
		let mut key = CSliceMut::new(key);
		let der_payload = CSlice::new(der_payload);
		
		let user_secret = user_secret.map(|s| CSlice::new(s));
		
		// Map optionals to pointers
		let user_secret: *const CSlice = user_secret.as_ref().map(|s| s as _)
			.unwrap_or(ptr::null());
		
		// Call function
		unsafe{ (self.open)(&mut key, der_tag, &der_payload, user_secret) }.check()?;
		Ok(key.len)
	}
}