mod ffi;
//use std::ptr::copy;
use crate::ffi::{ CSlice, CError, errno::* };


const TEST_USER_SECRET: &[u8] = b"Testolope";
pub static FORMAT_UID: &[u8; 64] =
	b"TestCapsuleFormat__________.3A0351A7-FE90-4383-9E68-FCC20033D5F1";


#[no_mangle]
pub extern "C" fn init(api_version: u8, _log_level: u8) -> CError {
	match api_version {
		1 => ok!(),
		_ => err!(EINIT, "Invalid API version", 0)
	}
}

#[no_mangle]
pub extern "C" fn capsule_format_uid() -> [u8; 64] {
	*FORMAT_UID
}


#[no_mangle]
pub extern "C" fn capsule_key_ids(id_buffer: *mut CSlice) -> CError {
	// Unwrap pointers
	let _id_buffer = unsafe{ id_buffer.as_mut().unwrap() };
	ok!()
}


#[no_mangle]
pub extern "C" fn seal(payload: *mut CSlice, key: *const CSlice, _capsule_key_id: *const CSlice,
	user_secret: *const CSlice) -> CError
{
	// Check pointer
	let payload = unsafe{ payload.as_mut() }.unwrap();
	let key = unsafe{ key.as_ref() }.unwrap().slice();
	let user_secret = unsafe{ user_secret.as_ref() };
	
	// Check `user_secret` (note that this is inherently insecure and for demo-purposes only)
	let user_secret = match user_secret {
		Some(user_secret) => user_secret.slice(),
		None => return err!(EPERM, "Authentication is required", 1)
	};
	if user_secret != TEST_USER_SECRET {
		return err!(EACCESS, "Invalid authentication", u64::max_value())
	}
	
	// "Encrypt" the key by reversing it and write it to `payload`
	let key: Vec<u8> = key.iter().map(|b| *b).rev().collect();
	match payload.write(&key) {
		Ok(_) => ok!(),
		Err(e) => e
	}
}

#[no_mangle]
pub extern "C" fn open(key: *mut CSlice, payload: *const CSlice, user_secret: *const CSlice)
	-> CError
{
	// Check pointer
	let key = unsafe{ key.as_mut() }.unwrap();
	let payload = unsafe{ payload.as_ref() }.unwrap().slice();
	let user_secret = unsafe{ user_secret.as_ref() };
	
	// Check `user_secret` (note that this is inherently insecure and for demo-purposes only)
	let user_secret = match user_secret {
		Some(user_secret) => user_secret.slice(),
		None => return err!(EPERM, "Authentication is required", 1)
	};
	if user_secret != TEST_USER_SECRET {
		return err!(EACCESS, "Invalid authentication", u64::max_value())
	}
	
	// "Decrypt" the key by reversing it and write it to `key`
	let payload: Vec<u8> = payload.iter().map(|b| *b).rev().collect();
	match key.write(&payload) {
		Ok(_) => ok!(),
		Err(e) => e
	}
}