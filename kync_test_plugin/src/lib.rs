mod ffi;

use ffi::{ MutPtrExt, SliceTExt, WriteTExt, sys };
use std::{ ptr, os::raw::c_char };
use crate::ffi::sys::slice_t;


const API: u16 = 0x01_00;
const USER_SECRET: &[u8] = b"Testolope";
const UID: &[u8] = b"TestCapsuleFormat.3A0351A7-FE90-4383-9E68-FCC20033D5F1";
const CONFIGS: &[&[u8]] = &[b"Default"];


/// Logs some text
fn log(s: impl AsRef<str>) {
	println!("{}", s.as_ref())
}

/// Converts a `Result<(), *const c_char>>` to a nullable error pointer
fn try_catch(f: impl FnOnce() -> Result<(), *const c_char>) -> *const c_char {
	f().err().unwrap_or(ptr::null())
}


/// Initializes the library with a specific API version and a logging level
///
/// Returns `NULL` on success or a pointer to a static error description
#[no_mangle]
extern "C" fn init(api: u16, _log_level: u8) -> *const c_char {
	match api {
		API => ptr::null(),
		_ => b"Unsupported API version\0".as_ptr().cast()
	}
}


/// Queries the plugin/format ID
///
/// Returns `NULL` on success or a pointer to a static error description
#[no_mangle]
extern "C" fn id(sink: *mut sys::write_t) -> *const c_char {
	try_catch(|| sink.checked_write(UID))
}


/// Queries all possible configs and writes them as separate segments
///
/// Returns `NULL` on success or a pointer to a static error description
#[no_mangle]
extern "C" fn configs(sink: *mut sys::write_t) -> *const c_char {
	try_catch(|| CONFIGS.iter().try_for_each(|c| sink.checked_write(c)))
}


/// Sets an optional application specific context if supported (useful to name the keys better etc.)
///
/// Returns `NULL` on success/if unsupported or a pointer to a static error description if a context
/// is supported by the plugin but could not be set
#[no_mangle]
extern "C" fn set_context(_context: *const sys::slice_t) -> *const c_char {
	ptr::null()
}


/// Queries the authentication requirements to protect a secret for a specific config
///
/// Returns `NULL` on success or a pointer to a static error description
#[no_mangle]
extern "C" fn auth_info_protect(is_required: *mut u8, retries: *mut u64, config: *const slice_t)
	-> *const c_char
{
	try_catch(|| {
		// Validate config
		if !CONFIGS.contains(&config.checked_slice()?) {
			Err(b"Invalid configuration\0".as_ptr().cast())?
		}
		
		// Set requirements
		is_required.checked_set(1)?;
		retries.checked_set(u64::max_value())?;
		Ok(())
	})
}


/// Queries the authentication requirements to recover a secret for a specific config
///
/// Returns `NULL` on success or a pointer to a static error description
#[no_mangle]
extern "C" fn auth_info_recover(is_required: *mut u8, retries: *mut u64, config: *const slice_t)
	-> *const c_char
{
	try_catch(|| {
		// Validate config
		if !CONFIGS.contains(&config.checked_slice()?) {
			Err(b"Invalid configuration\0".as_ptr().cast())?
		}
		
		// Set requirements
		is_required.checked_set(1)?;
		retries.checked_set(u64::max_value())?;
		Ok(())
	})
}


/// Protects some data
///
/// Returns `NULL` on success or a pointer to a static error description
#[no_mangle]
extern "C" fn protect(sink: *mut sys::write_t, data: *const sys::slice_t,
	config: *const sys::slice_t, auth: *const sys::slice_t) -> *const c_char
{
	try_catch(|| {
		// Validate config
		if !CONFIGS.contains(&config.checked_slice()?) {
			Err(b"Invalid configuration\0".as_ptr().cast())?
		}
		
		// Validate authentication
		let auth = auth.checked_slice()
			.map_err(|_| b"Missing authentication parameter\0".as_ptr().cast())?;
		if auth != USER_SECRET {
			Err(b"Invalid authentication\0".as_ptr().cast())?
		}
		
		// Obfuscate the data by reversing it
		let mut data: Vec<u8> = data.checked_slice()?.to_vec();
		data.reverse();
		sink.checked_write(data)
	})
}


/// Opens `data` to `sink` using `auth` and `config`
///
/// Returns `NULL` on success or a pointer to a static error description
#[no_mangle]
extern "C" fn recover(sink: *mut sys::write_t, data: *const sys::slice_t, auth: *const sys::slice_t)
	-> *const c_char
{
	try_catch(|| {
		// Validate authentication
		let auth = auth.checked_slice()
			.map_err(|_| b"Missing authentication parameter\0".as_ptr().cast())?;
		if auth != USER_SECRET {
			Err(b"Invalid authentication\0".as_ptr().cast())?
		}
		
		// Recover the data
		let mut data = data.checked_slice()?.to_vec();
		data.reverse();
		sink.checked_write(data)
	})
}


#[test]
fn test_types() {
	struct Fns {
		_init: sys::init,
		_id: sys::id,
		_configs: sys::configs,
		_set_context: sys::set_context,
		_auth_info_protect: sys::auth_info_protect,
		_auth_info_recover: sys::auth_info_recover,
		_protect: sys::protect,
		_recover: sys::recover
	}
	let _fns = Fns {
		_init: Some(init),
		_id: Some(id),
		_configs: Some(configs),
		_set_context: Some(set_context),
		_auth_info_protect: Some(auth_info_protect),
		_auth_info_recover: Some(auth_info_recover),
		_protect: Some(protect),
		_recover: Some(recover)
	};
}