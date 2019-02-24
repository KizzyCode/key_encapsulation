use crate::{ KyncError, CSource, AsCSource, CSink, AsCSink, ffi::{ CError, FromCStr } };
use std::path::Path;
use libloading::Library;
use crate::ErrorKind;
use std::os::raw::c_char;


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
	capsule_format_uid: unsafe extern "C" fn() -> *const c_char,
	
	crypto_item_ids: unsafe extern "C" fn(id_buffer: CSink) -> CError,
	
	seal: unsafe extern "C" fn(
		sink: CSink, key: CSource,
		crypto_item_id: CSource, user_secret: CSource
	) -> CError,
	open: unsafe extern "C" fn(
		sink: CSink, capsule: CSource,
		user_secret: CSource
	) -> CError,
	
	_library: Library
}
impl Plugin {
	/// Load the library
	pub fn load(path: impl AsRef<Path>) -> Result<Self, KyncError> {
		// Determine the log-level
		let log_level = if cfg!(debug_assertions) { 1 } else { 0 };
		
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
		let init: unsafe extern "C" fn(u8) -> u8 = *unsafe{ library.get(b"init\0")? };
		if unsafe{ init(log_level) } != API_VERSION { Err(ErrorKind::Unsupported)? }
		
		// Create plugin
		Ok(Self {
			capsule_format_uid: *unsafe{ library.get(b"capsule_format_uid\0")? },
			
			crypto_item_ids: *unsafe{ library.get(b"crypto_item_ids\0")? },
			seal: *unsafe{ library.get(b"seal\0")? },
			open: *unsafe{ library.get(b"open\0")? },
			
			_library: library
		})
	}
	
	/// The capsule format UID
	pub fn capsule_format_uid(&self) -> String {
		unsafe{ String::from_c_str((self.capsule_format_uid)()) }.unwrap().0
	}
	
	/// The available crypto item IDs
	pub fn crypto_item_ids(&self) -> Result<Vec<String>, KyncError> {
		// Collect all key UIDs
		let mut buf = Vec::new();
		unsafe{ (self.crypto_item_ids)(buf.as_c_sink()) }.check()?;
		
		// Parse all key UIDs
		let (mut uids, mut pos) = (Vec::new(), 0);
		while pos < buf.len() {
			// Read string and increment the position by `len + 1` (for the `'\0'`-byte)
			let (uid, len) = String::from_c_str_slice(&buf[pos..]).unwrap();
			pos += len + 1;
			uids.push(uid);
		}
		Ok(uids)
	}
	
	/// Seals a key into `buf` and returns the amount of bytes written
	pub fn seal(&self, buf: &mut Vec<u8>, key: &[u8],
		crypto_item_id: Option<&[u8]>, user_secret: Option<&[u8]>)
		-> Result<usize, KyncError>
	{
		unsafe{ (self.seal)(
			buf.as_c_sink(), key.as_c_source(),
			crypto_item_id.as_c_source(), user_secret.as_c_source()
		) }.check()?;
		Ok(buf.len())
	}
	
	/// Opens the `capsule` into `buf` and returns the amount of bytes written
	pub fn open(&self, buf: &mut Vec<u8>, capsule: &[u8], user_secret: Option<&[u8]>)
		-> Result<usize, KyncError>
	{
		// Call function
		unsafe{ (self.open)(buf.as_c_sink(), capsule.as_c_source(), user_secret.as_c_source()) }
			.check()?;
		Ok(buf.len())
	}
}