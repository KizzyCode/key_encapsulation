use crate::{
	KyncError, KyncErrorKind,
	ffi::{ StaticCharPtrExt, Slice, Writer, sys }
};
use std::{ ptr, path::Path };
use libloading::Library;


/// The current API version
const API_VERSION: u16 = 0x01_00;


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
	id: sys::id,
	configs: sys::configs,
	set_context: sys::set_context,
	auth_info_protect: sys::auth_info_protect,
	auth_info_recover: sys::auth_info_recover,
	protect: sys::protect,
	recover: sys::recover,
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
			libloading::os::unix::Library::open(Some(path.as_ref()), 0x2 | 0x1000)?.into()
		};
		#[cfg(not(target_os = "linux"))]
		let library = Library::new(path.as_ref())?;
		
		// Init plugin and validate the API version
		let log_level = match cfg!(debug_assertions) {
			true => 1,
			false => 0
		};
		let init: sys::init = *unsafe{ library.get(b"init\0")? };
		unsafe{ init.unwrap()(API_VERSION, log_level) }.check(KyncErrorKind::InitError)?;
		
		// Create plugin
		Ok(Self {
			id: *unsafe{ library.get(b"id\0")? },
			configs: *unsafe{ library.get(b"configs\0")? },
			set_context: *unsafe{ library.get(b"set_context\0")? },
			auth_info_protect: *unsafe{ library.get(b"auth_info_protect\0")? },
			auth_info_recover: *unsafe{ library.get(b"auth_info_recover\0")? },
			protect: *unsafe{ library.get(b"protect\0")? },
			recover: *unsafe{ library.get(b"recover\0")? },
			_library: library
		})
	}
	
	/// The plugin/format ID
	pub fn id(&self) -> Result<Vec<u8>, KyncError> {
		let mut sink = Writer::new();
		unsafe{ self.id.unwrap()(sink.write_t()) }.check(KyncErrorKind::IdError)?;
		Ok(sink.into())
	}
	
	/// All possible configs
	pub fn configs(&self) -> Result<Vec<Vec<u8>>, KyncError> {
		let mut sink = Writer::new();
		unsafe{ self.configs.unwrap()(sink.write_t()) }.check(KyncErrorKind::ConfigsError)?;
		Ok(sink.into())
	}
	
	/// Sets an optional application specific context if supported (useful to assign better names
	/// etc.)
	pub fn set_context(&self, context: &[u8]) -> Result<(), KyncError> {
		let context = Slice::from(context);
		unsafe{ self.set_context.unwrap()(context.slice_t()) }
			.check(KyncErrorKind::SetContextError)
	}
	
	/// Checks if an authentication is required to protect a secret and gets the number of retries
	/// left
	pub fn auth_info_protect(&self, config: &[u8]) -> Result<(bool, u64), KyncError> {
		let config = Slice::from(config);
		let (mut required, mut retries) = (0u8, 0u64);
		unsafe{ self.auth_info_protect.unwrap()(&mut required, &mut retries, config.slice_t()) }
			.check(KyncErrorKind::AuthInfoError)?;
		Ok((required != 0, retries))
	}
	
	/// Checks if an authentication is required to recover a secret and gets the number of retries
	/// left
	pub fn auth_info_recover(&self, config: &[u8]) -> Result<(bool, u64), KyncError> {
		let config = Slice::from(config);
		let (mut required, mut retries) = (0u8, 0u64);
		unsafe{ self.auth_info_recover.unwrap()(&mut required, &mut retries, config.slice_t()) }
			.check(KyncErrorKind::AuthInfoError)?;
		Ok((required != 0, retries))
	}
	
	/// Protects `data`
	pub fn protect(&self, data: &[u8], config: &[u8], auth: Option<&[u8]>)
		-> Result<Vec<u8>, KyncError>
	{
		// Create the C structs
		let mut sink = Writer::new();
		let data = Slice::from(data);
		let config = Slice::from(config);
		let auth = auth.map(|s| Slice::from(s));
		
		// Call `protect`
		let auth = auth.as_ref().map(|s| s.slice_t() as *const sys::slice_t)
			.unwrap_or(ptr::null());
		unsafe{ self.protect.unwrap()(sink.write_t(), data.slice_t(), config.slice_t(), auth) }
			.check(KyncErrorKind::ProtectError)?;
		Ok(sink.into())
	}
	
	/// Recovers some protected `data`
	pub fn recover(&self, data: &[u8], auth: Option<&[u8]>) -> Result<Vec<u8>, KyncError> {
		// Create the C structs
		let mut sink = Writer::new();
		let data = Slice::from(data);
		let auth = auth.map(|s| Slice::from(s));
		
		// Call `recover`
		let auth = auth.as_ref().map(|s| s.slice_t() as *const sys::slice_t)
			.unwrap_or(ptr::null());
		unsafe{ self.recover.unwrap()(sink.write_t(), data.slice_t(), auth) }
			.check(KyncErrorKind::ProtectError)?;
		Ok(sink.into())
	}
}