/// Checks if `$condition` is true or returns an `Err($error)` otherwise
macro_rules! check {
	($condition:expr, $error:expr) => (if !$condition { $error });
}


mod ffi;
use crate::ffi::{ FromCStr, CSlice, CSliceMut, CError, errno::* };


const TEST_USER_SECRET: &[u8] = b"Testolope";
pub static FORMAT_UID: &[u8] = b"TestCapsuleFormat.3A0351A7-FE90-4383-9E68-FCC20033D5F1";


#[no_mangle]
pub extern "C" fn init(api_version: u8, _log_level: u8) -> CError {
	match api_version {
		1 => ok!(),
		_ => err!(EINIT, "Invalid API version", 0)
	}
}

#[no_mangle]
pub extern "C" fn capsule_format_uid() -> CSlice<'static> {
	CSlice::new(FORMAT_UID)
}

#[no_mangle]
pub extern "C" fn buf_len_max(fn_name: *const CSlice) -> usize {
	// Unwrap pointers
	let fn_name = unsafe{ fn_name.as_ref() }.unwrap();
	
	// Get max length
	match String::from_c_str(unsafe{ fn_name.as_slice() }).as_str() {
		"capsule_key_ids" => 0,
		"seal" => 1024,
		"open" => 1024,
		_ => 0
	}
}


#[no_mangle] pub extern "C" fn capsule_key_ids(id_buffer: *mut CSliceMut) -> CError {
	// Unwrap pointers
	let id_buffer = unsafe{ id_buffer.as_mut() }.unwrap();
	
	// Set buffer length to 0
	id_buffer.len = 0;
	ok!()
}

#[no_mangle] pub extern "C" fn seal(der_tag: *mut u8, der_payload: *mut CSliceMut,
	key: *const CSlice, _capsule_key_id: *const CSlice, user_secret: *const CSlice) -> CError
{
	// Check pointer
	let der_tag = unsafe{ der_tag.as_mut() }.unwrap();
	let der_payload = unsafe{ der_payload.as_mut().unwrap() };
	let key = unsafe{ key.as_ref().unwrap().as_slice() };
	let user_secret = unsafe{ user_secret.as_ref() };
	
	// Unwrap `user_secret`
	let user_secret = match user_secret {
		Some(user_secret) => unsafe{ user_secret.as_slice() },
		None => err!(EPERM, "Authentication is required", 1)
	};
	
	// Check `user_secret` (note that this is inherently insecure)
	match user_secret {
		TEST_USER_SECRET => (),
		_ => err!(EACCESS, "Invalid authentication", u64::max_value())
	}
	
	// Set payload length and unwrap it
	check!(der_payload.len >= key.len(), err!(EINVAL, "`der_payload` is too small", 1));
	der_payload.len = key.len();
	let der_payload = unsafe{ der_payload.as_slice_mut() };
	
	// Encode
	*der_tag = 0x04;
	der_payload.copy_from_slice(key);
	ok!()
}

#[no_mangle] pub extern "C" fn open(key: *mut CSliceMut, der_tag: u8, der_payload: *const CSlice,
	user_secret: *const CSlice) -> CError
{
	// Check pointer
	let key = unsafe{ key.as_mut().unwrap() };
	let der_payload = unsafe{ der_payload.as_ref().unwrap().as_slice() };
	let user_secret = unsafe{ user_secret.as_ref() };
	
	// Unwrap and check `auth_info` (note that this is inherently insecure)
	let user_secret = match user_secret {
		Some(user_secret) => unsafe{ user_secret.as_slice() },
		None => err!(EPERM, "Authentication is required", 1)
	};
	match user_secret {
		TEST_USER_SECRET => (),
		_ => err!(EACCESS, "Invalid authentication", u64::max_value())
	}
	
	// Check payload
	check!(der_tag == 0x04, err!(EILSEQ, "Invalid capsule", 0));
	
	// Check and unwrap `key`
	check!(key.len >= der_payload.len(), err!(EINVAL, "`key` is too small", 0));
	key.len = der_payload.len() ;
	let key = unsafe{ key.as_slice_mut() };
	
	// Copy key
	key.copy_from_slice(der_payload);
	ok!()
}