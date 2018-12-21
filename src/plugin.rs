use crate::{ Error, PluginError };
use ::{
	libloading::Library,
	std::{ path::Path, marker::PhantomData, os::raw::c_char, ffi::CStr }
};


/// The constant C-API slice type
#[repr(C)]
pub struct CSlice<'a> {
	pub data: *const u8,
	pub data_len: usize,
	_lifetime: PhantomData<&'a[u8]>
}
impl<'a> CSlice<'a> {
	/// Creates a new `CSlice` (aka `slice_t`) over `slice`
	pub fn with(slice: &'a[u8]) -> Self {
		Self{ data: slice.as_ptr(), data_len: slice.len(), _lifetime: PhantomData }
	}
}
/// The mutable C-API slice type
#[repr(C)]
pub struct CSliceMut<'a> {
	pub data: *mut u8,
	pub data_len: usize,
	_lifetime: PhantomData<&'a[u8]>
}
impl<'a> CSliceMut<'a> {
	/// Creates a new `CSliceMut` (aka `slice_t`) over `slice`
	pub fn with(slice: &'a mut[u8]) -> Self {
		Self{ data: slice.as_mut_ptr(), data_len: slice.len(), _lifetime: PhantomData }
	}
}


/// A key capsule plugin (see "Kync.asciidoc" for further API documentation)
pub struct Plugin {
	pub capsule_format_uid: unsafe extern fn() -> *const c_char,
	pub buf_len_max: unsafe extern fn(fn_name: *const c_char) -> usize,
	
	pub capsule_key_ids: unsafe extern fn(buf: *mut CSliceMut) -> u8,
	pub seal_key: unsafe extern fn(
		der_tag: *mut u8, der_payload: *mut CSliceMut, key: *const CSlice,
		capsule_key_id: *const c_char, auth_info: *const CSlice
	) -> u8,
	pub open_capsule: unsafe extern fn(
		key: *mut CSliceMut, der_tag: u8, der_payload: *const CSlice,
		auth_info: *const CSlice
	) -> u8,
	
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
				library.get::<unsafe extern fn(u8) -> *const c_char>(b"init\0")?;
			let api_version: *const c_char = init(log_level);
			
			// Check for NULL-ptr and validate API version
			check!(!api_version.is_null(), PluginError::InitializationError);
			check!(
				CStr::from_ptr(api_version).to_string_lossy() == "de.KizzyCode.Kync.ApiV1",
				Error::Unsupported
			);
		}
		
		// Create plugin
		Ok(Self {
			capsule_format_uid: *unsafe{ library.get(b"capsule_format_uid\0")? },
			buf_len_max: *unsafe{ library.get(b"buf_len_max\0")? },
			
			capsule_key_ids: *unsafe{ library.get(b"capsule_key_ids\0")? },
			seal_key: *unsafe{ library.get(b"seal_key\0")? },
			open_capsule: *unsafe{ library.get(b"open_capsule\0")? },
			
			_library: library
		})
	}
}