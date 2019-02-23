mod ffi;
use crate::ffi::{ CSource, CSink, CError };


const API_VERSION: u8 = 1;
const TEST_USER_SECRET: &[u8] = b"Testolope";
static FORMAT_UID: &'static [u8] =
	b"TestCapsuleFormat.3A0351A7-FE90-4383-9E68-FCC20033D5F1\0";


/// This function initializes the library, sets the log_level and returns the API version
#[no_mangle]
pub extern "C" fn init(_log_level: u8) -> u8 {
	API_VERSION
}

/// This function returns a const pointer the plugin’s capsule format UID
#[no_mangle]
pub extern "C" fn capsule_format_uid() -> *const u8 {
	FORMAT_UID.as_ptr()
}


/// This function writes all available capsule key IDs as concatenated `[u8; 256]`-arrays into `ids`
#[no_mangle]
pub extern "C" fn capsule_key_ids(_ids: CSink) -> CError {
	CError::enokey().desc(b"This plugin does not use a key store\0")
}


/// This function seals the key bytes in `key` and writes the resulting data to `sink`
#[no_mangle]
pub extern "C" fn seal(mut sink: CSink, key: CSource, capsule_key_id: CSource, user_secret: CSource)
	-> CError
{
	// Validate that we have NO capsule ID
	if capsule_key_id.data().is_some() {
		return CError::einval(2).desc(b"This plugin does not use a key store\0")
	}
	
	// Check that we have a key
	let key = match key.data() {
		Some(key) => key,
		None => return CError::einval(1).desc(b"The `key` is obligatory\0")
	};
	
	// Check `user_secret` (note that this is inherently insecure and for demo-purposes only)
	match user_secret.data() {
		Some(TEST_USER_SECRET) => (),
		Some(_) => return CError::eacces(None).desc(b"Invalid secret\0"),
		None => return CError::eperm(true).desc(b"Secret is required\0")
	}
	
	// "Encrypt" the key by reversing it and write it to `sink`
	match sink.data(key.len()) {
		Some(sink) =>
			key.iter().rev().enumerate().for_each(|(i, b)| sink[i] = *b),
		None => return CError::enobuf(key.len() as u64)
			.desc(b"Failed to write to sink\0")
	};
	CError::ok()
}


/// This function opens a key `capsule` and writes the resulting key bytes into `sink`
#[no_mangle]
pub extern "C" fn open(mut sink: CSink, capsule: CSource, user_secret: CSource) -> CError {
	// Check that we have a capsule
	let capsule = match capsule.data() {
		Some(capsule) => capsule,
		None => return CError::einval(1).desc(b"The `capsule` is obligatory\0")
	};
	
	// Check `user_secret` (note that this is inherently insecure and for demo-purposes only)
	match user_secret.data() {
		Some(TEST_USER_SECRET) => (),
		Some(_) => return CError::eacces(None).desc(b"Invalid secret\0"),
		None => return CError::eperm(true).desc(b"Secret is required\0")
	}
	
	// "Decrypt" the key by reversing it and write it to `sink`
	match sink.data(capsule.len()) {
		Some(sink) =>
			capsule.iter().rev().enumerate().for_each(|(i, b)| sink[i] = *b),
		None => return CError::enobuf(capsule.len() as u64)
			.desc(b"Failed to write to sink\0")
	};
	CError::ok()
}