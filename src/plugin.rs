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
	
	capsule_key_ids: unsafe extern "C" fn(id_buffer: CSink) -> CError,
	
	seal: unsafe extern "C" fn(
		sink: CSink, key: CSource,
		capsule_key_id: CSource, user_secret: CSource
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
		let init: unsafe extern "C" fn(u8) -> u8 = *unsafe{ library.get(b"init\0")? };
		if unsafe{ init(log_level) } != API_VERSION { Err(ErrorKind::Unsupported)? }
		
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
	pub fn capsule_format_uid(&self) -> String {
		unsafe{ String::from_c_str((self.capsule_format_uid)()) }.unwrap()
	}
	
	/// The available capsule keys
	pub fn capsule_key_ids(&self) -> Result<Vec<String>, KyncError> {
		// Collect all key UIDs
		let mut buf = Vec::new();
		unsafe{ (self.capsule_key_ids)(buf.as_c_sink()) }.check()?;
		assert_eq!(buf.len() % 256, 0);
		
		// Parse all key UIDs
		let uids = buf.chunks(256)
			.map(|uid| unsafe{ String::from_c_str_limit(uid.as_ptr(), 256) })
			.map(|s| s.unwrap())
			.collect();
		
		Ok(uids)
	}
	
	/// Seals a key into `buf` and returns the amount of bytes written
	pub fn seal(&self, buf: &mut Vec<u8>, key: &[u8],
		capsule_key_id: Option<&[u8]>, user_secret: Option<&[u8]>)
		-> Result<usize, KyncError>
	{
		unsafe{ (self.seal)(
			buf.as_c_sink(), key.as_c_source(),
			capsule_key_id.as_c_source(), user_secret.as_c_source()
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