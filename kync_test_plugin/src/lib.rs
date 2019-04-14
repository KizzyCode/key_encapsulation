mod ffi;
use ffi::{ ErrorExt, error_t };
use std::slice;


const API_VERSION: u8 = 1;
const USER_SECRET: &[u8] = b"Testolope";
static UID: &[u8] = b"TestCapsuleFormat.3A0351A7-FE90-4383-9E68-FCC20033D5F1";


/// Initializes the plugin
#[no_mangle]
pub extern "C" fn init(api_version: *mut u8, _log_level: u8) {
	assert!(!api_version.is_null());
	
	unsafe{ *api_version = API_VERSION }
}

/// Computes the buffer size necessary for a call to `fn_name` which will process `input_len` bytes
/// of input and writes the result to `buf_len`
#[no_mangle]
pub extern "C" fn buf_len(buf_len: *mut usize, fn_name: *const u8, fn_name_len: usize,
	input_len: usize)
{
	assert!(!buf_len.is_null());
	assert!(!fn_name.is_null());
	
	// Get the function name
	let fn_name = unsafe{ slice::from_raw_parts(fn_name, fn_name_len) };
	let len = match fn_name {
		b"capsule_format_uid" => UID.len(),
		b"crypto_item_ids" => 0,
		b"seal" => input_len,
		b"open" => input_len,
		_ => 0
	};
	unsafe{ *buf_len = len }
}

/// Writes the plugin UID to `uid`
#[no_mangle]
pub extern "C" fn capsule_format_uid(uid: *mut u8, uid_written: *mut usize) {
	assert!(!uid.is_null());
	
	// Copy the UID
	let uid = unsafe{ slice::from_raw_parts_mut(uid, UID.len()) };
	uid.copy_from_slice(UID);
	unsafe{ *uid_written = UID.len() }
}


/// Writes all crypto item IDs as `\0`-terminated, concatenated UTF-8 strings to `_buf`
#[no_mangle]
pub extern "C" fn crypto_item_ids(_buf: *mut u8, _buf_written: *mut usize) -> *const error_t {
	error_t::enotfound().set_desc(b"This plugin does not support multiple crypto items")
}


/// Seals `key` into `buf`
#[no_mangle]
pub extern "C" fn seal(buf: *mut u8, buf_written: *mut usize, key: *const u8, key_len: usize,
	crypto_item_id: *const u8, _crypto_item_id_len: usize, user_secret: *const u8,
	user_secret_len: usize) -> *const error_t
{
	assert!(!buf.is_null());
	assert!(!buf_written.is_null());
	assert!(!key.is_null());
	
	// Validate that we have NO crypto item ID but a user secret and get the key
	match crypto_item_id.is_null() {
		true => (),
		false => return error_t::einval(4).set_desc(b"Multiple crypto items are unsupported")
	};
	let user_secret = match user_secret.is_null() {
		true => return error_t::eperm(true)
			.set_desc(b"A user secret is obligatory"),
		false => unsafe{ slice::from_raw_parts(user_secret, user_secret_len) }
	};
	
	// Get buffer and key
	let buf = unsafe{ slice::from_raw_parts_mut(buf, key_len) };
	let key = unsafe{ slice::from_raw_parts(key, key_len) };
	
	// Check `user_secret` (note that this is inherently insecure and for demo-purposes only)
	match user_secret {
		USER_SECRET => (),
		_ => return error_t::eacces(None).set_desc(b"Invalid user secret")
	}
	
	// "Encrypt" the key by reversing it
	key.iter().rev().enumerate().for_each(|(i, b)| buf[i] = *b);
	unsafe{ *buf_written = key.len() };
	error_t::ok()
}


/// Opens `capsule` into `buf`
#[no_mangle]
pub extern "C" fn open(buf: *mut u8, buf_written: *mut usize, capsule: *const u8,
	capsule_len: usize, user_secret: *const u8, user_secret_len: usize) -> *const error_t
{
	assert!(!buf.is_null());
	assert!(!buf_written.is_null());
	assert!(!capsule.is_null());
	
	// Validate that we have a user secret
	let user_secret = match user_secret.is_null() {
		true => return error_t::eperm(true)
			.set_desc(b"A user secret is obligatory"),
		false => unsafe{ slice::from_raw_parts(user_secret, user_secret_len) }
	};
	
	// Get buffer and capsule
	let buf = unsafe{ slice::from_raw_parts_mut(buf, capsule_len) };
	let capsule = unsafe{ slice::from_raw_parts(capsule, capsule_len) };
	
	// Check `user_secret` (note that this is inherently insecure and for demo-purposes only)
	match user_secret {
		USER_SECRET => (),
		_ => return error_t::eacces(None).set_desc(b"Invalid user secret")
	}
	
	// "Decrypt" the key by reversing it
	capsule.iter().rev().enumerate().for_each(|(i, b)| buf[i] = *b);
	unsafe{ *buf_written = capsule.len() };
	error_t::ok()
}