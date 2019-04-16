use crate::{
	KyncError, ErrorKind,
	ffi::{ self, ErrorExt}
};
use std::{ ptr, path::Path };
use libloading::Library;


/// The current API version
const API_VERSION: u8 = 1;


/// The current operating system's default dynamic library prefix (e.g. `"lib"` for Linux)
#[cfg(any(target_os = "windows", target_family = "unix"))]
pub fn os_default_prefix() -> &'static str {
	match true {
		_ if cfg!(target_os = "windows") => "",
		_ if cfg!(target_family = "unix") => "lib",
		_ => unreachable!()
	}
}
/// The current operating system's default dynamic library extension (e.g. `"so"` for Linux)
#[cfg(any(target_os = "windows", target_family = "unix"))]
pub fn os_default_suffix() -> &'static str {
	match true {
		_ if cfg!(target_os = "windows") => "dll",
		_ if cfg!(target_os = "macos") => "dylib",
		_ if cfg!(target_family = "unix") => "so",
		_ => unreachable!()
	}
}


/// A key capsule plugin (see "Kync.asciidoc" for further API documentation)
pub struct Plugin {
	buf_len: ffi::BufLenFn,
	capsule_format_uid: ffi::CapsuleFormatUidFn,
	crypto_item_ids: ffi::CryptoItemIdsFn,
	seal: ffi::SealFn,
	open: ffi::OpenFn,
	
	_library: Library
}
impl Plugin {
	/// Load the library
	pub fn load(path: impl AsRef<Path>) -> Result<Self, KyncError> {
		// Load library
		#[cfg(target_os = "linux")]
		let library: Library = {
			// Load library with RTLD_NOW | RTLD_NODELETE to fix a SIGSEGV
			// (see https://github.com/nagisa/rust_libloading/issues/41)
			::libloading::os::unix::Library::open(Some(path.as_ref()), 0x2 | 0x1000)?.into()
		};
		#[cfg(not(target_os = "linux"))]
		let library = Library::new(path.as_ref())?;
		
		// Init plugin and validate the API version
		let log_level = if cfg!(debug_assertions) { 1 } else { 0 };
		let mut api_version = 0;
		
		unsafe{ library.get::<ffi::InitFn>(b"init\0")?(&mut api_version, log_level) };
		if api_version != API_VERSION { Err(ErrorKind::Unsupported)? }
		
		// Create plugin
		Ok(Self {
			buf_len: *unsafe{ library.get(b"buf_len\0")? },
			capsule_format_uid: *unsafe{ library.get(b"capsule_format_uid\0")? },
			crypto_item_ids: *unsafe{ library.get(b"crypto_item_ids\0")? },
			seal: *unsafe{ library.get(b"seal\0")? },
			open: *unsafe{ library.get(b"open\0")? },
			
			_library: library
		})
	}
	
	/// Computes the buffer length required for a call to `fn_name` with an `input_len`-sized input
	fn buf_len(&self, fn_name: &[u8], input_len: usize) -> usize {
		let mut buf_len = 0;
		unsafe{ (self.buf_len)(&mut buf_len, fn_name.as_ptr(), fn_name.len(), input_len) }
		buf_len
	}
	
	/// Returns the capsule format UID
	pub fn capsule_format_uid(&self) -> String {
		// Create buffer
		let mut format_uid =
			vec![0; self.buf_len(b"capsule_format_uid", 0)];
		let mut format_uid_len = 0;
		
		// Get data, truncate vector and create string
		unsafe{ (self.capsule_format_uid)(format_uid.as_mut_ptr(), &mut format_uid_len) }
		format_uid.truncate(format_uid_len);
		String::from_utf8(format_uid).unwrap()
	}
	
	/// The available crypto item IDs
	pub fn crypto_item_ids(&self) -> Result<Vec<String>, KyncError> {
		// Allocate buffer
		let mut buf = vec![0; self.buf_len(b"crypto_item_ids", 0)];
		let mut buf_written = 0;
		
		// Collect all IDs
		unsafe{ (self.crypto_item_ids)(buf.as_mut_ptr(), &mut buf_written) }.check()?;
		buf.truncate(buf_written);
		
		// Parse all item IDs
		let ids = buf.split(|b| *b == 0)
			.map(|b| String::from_utf8(b.to_vec()).unwrap())
			.collect();
		Ok(ids)
	}
	
	/// The buffer size necessary for a call to `seal`
	pub fn seal_buf_len(&self, input_len: usize) -> usize {
		self.buf_len(b"seal", input_len)
	}
	/// Seals a key into `buf` and returns the amount of bytes written
	pub fn seal(&self, buf: &mut[u8], key: &[u8], crypto_item_id: Option<&[u8]>,
		user_secret: Option<&[u8]>) -> Result<usize, KyncError>
	{
		// Validate the buffer
		assert!(buf.len() >= self.seal_buf_len(key.len()));
		
		// Map crypto item ID and user secret
		let (crypto_item_id, crypto_item_id_len) = match crypto_item_id {
			Some(id) => (id.as_ptr(), id.len()),
			None => (ptr::null(), 0)
		};
		let (user_secret, user_secret_len) = match user_secret {
			Some(secret) => (secret.as_ptr(), secret.len()),
			None => (ptr::null(), 0)
		};
		
		// Seal the key
		let mut buf_written = 0;
		unsafe{ (self.seal)(
			buf.as_mut_ptr(), &mut buf_written,
			key.as_ptr(), key.len(),
			crypto_item_id, crypto_item_id_len,
			user_secret, user_secret_len
		) }.check()?;
		
		Ok(buf_written)
	}
	
	/// The buffer size necessary for a call to `open`
	pub fn open_buf_len(&self, input_len: usize) -> usize {
		self.buf_len(b"open", input_len)
	}
	/// Opens the `capsule` into `buf` and returns the amount of bytes written
	pub fn open(&self, buf: &mut[u8], capsule: &[u8], user_secret: Option<&[u8]>)
		-> Result<usize, KyncError>
	{
		// Validate the buffer
		assert!(buf.len() >= self.open_buf_len(capsule.len()));
		
		// Map user secret
		let (user_secret, user_secret_len) = match user_secret {
			Some(secret) => (secret.as_ptr(), secret.len()),
			None => (ptr::null(), 0)
		};
		
		// Call function
		let mut buf_written = 0;
		unsafe{ (self.open)(
			buf.as_mut_ptr(), &mut buf_written,
			capsule.as_ptr(), capsule.len(),
			user_secret, user_secret_len
		) }.check()?;
		
		Ok(buf_written)
	}
}