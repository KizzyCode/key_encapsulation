use crate::{ Error, ffi_tools::{ CheckedDeref, CheckedDerefMut, CSlice, CSliceMut } };
use ::std::{ ffi::CStr, os::raw::c_char };


#[no_mangle] pub extern "C" fn init() -> *const c_char {
	b"de.KizzyCode.KeyCapsule.Api.v1\0".as_ptr() as _
}
#[no_mangle] pub extern "C" fn capsule_format_uid() -> *const c_char {
	b"TestCapsuleFormat.3A0351A7-FE90-4383-9E68-FCC20033D5F1\0".as_ptr() as _
}
#[no_mangle] pub extern "C" fn buf_len_max(fn_name: *const c_char) -> usize {
	// Check pointer
	assert!(!fn_name.is_null());

	// Get max length
	match unsafe{ CStr::from_ptr(fn_name) }.to_str().unwrap() {
		"capsule_key_ids" => 64,
		"seal_key" => 1024,
		"open_capsule" => 1024,
		_ => 0
	}
}


#[no_mangle] pub extern "C" fn capsule_key_ids(buf: *mut CSliceMut) -> u8 {
	// Check and unwrap pointer
	check!(!buf.is_null(), Error::ApiMisuse);
	let buf = buf.checked_deref_mut();
	
	// Declare keys and create slice over `buf`
	const KEYS: &[u8] = b"Key0\0Key1\0Key7\0";
	
	// Check space and copy keys
	let buf_slice = buf.as_slice_mut();
	check!(buf_slice.len() >= KEYS.len(), Error::ApiMisuse);
	buf_slice[..KEYS.len()].copy_from_slice(&KEYS);

	// Adjust `buf` and return
	buf.data_len = KEYS.len();
	0
}

#[no_mangle] pub extern "C" fn seal_key(der_tag: *mut u8, der_payload: *mut CSliceMut,
	key: *const CSlice, capsule_key_id: *const c_char, auth_info: *const CSlice) -> u8
{
	// Check pointer
	check!(!der_tag.is_null(), Error::ApiMisuse);
	check!(!der_payload.is_null(), Error::ApiMisuse);
	check!(!key.is_null(), Error::ApiMisuse);
	check!(!capsule_key_id.is_null(), Error::ApiMisuse);
	check!(!auth_info.is_null(), Error::ApiMisuse);

	// Unwrap pointer
	let der_tag = der_tag.checked_deref_mut();
	let der_payload = der_payload.checked_deref_mut();
	let key = key.checked_deref().as_slice();
	let capsule_key_id = unsafe{ CStr::from_ptr(capsule_key_id) }.to_str().unwrap();
	let auth_info = auth_info.checked_deref().as_slice();
	
	// Check `capsule_key_id == auth_info`
	match capsule_key_id {
		"Key0" | "Key1" | "Key7" => check!(
			capsule_key_id.as_bytes() == auth_info,
			Error::AuthenticationError
		),
		_ => return Error::ApiMisuse.to_errno()
	}

	// Check key length and buffer size
	let der_payload_slice = der_payload.as_slice_mut();
	check!(der_payload_slice.len() >= key.len() + 5, Error::ApiMisuse);

	// Encode
	*der_tag = 0x04;
	der_payload_slice[..4].copy_from_slice(capsule_key_id.as_bytes());
	der_payload_slice[4] = b':';
	der_payload_slice[5..5 + key.len()].copy_from_slice(key);

	// Adjust payload slice
	der_payload.data_len = 5 + key.len();
	0
}

#[no_mangle] pub extern "C" fn open_capsule(key: *mut CSliceMut, der_tag: u8,
	der_payload: *const CSlice, auth_info: *const CSlice) -> u8
{
	// Check pointer
	check!(!key.is_null(), Error::ApiMisuse);
	check!(!der_payload.is_null(), Error::ApiMisuse);
	check!(!auth_info.is_null(), Error::ApiMisuse);

	// Unwrap pointer
	let key = key.checked_deref_mut();
	let der_payload = der_payload.checked_deref().as_slice();
	let auth_info = auth_info.checked_deref().as_slice();
	
	// Check DER-tag and payload length
	check!(der_tag == 0x04, Error::InvalidData);
	check!(der_payload.len() >= 5, Error::InvalidData);

	// Destructure payload
	let capsule_key_id = &der_payload[..4];
	let colon = der_payload[4];
	let key_data = &der_payload[5..];

	// Check `capsule_key_id == auth_info` and colon
	match capsule_key_id {
		b"Key0" | b"Key1" | b"Key7" => check!(
			capsule_key_id == auth_info,
			Error::AuthenticationError
		),
		_ => return Error::NoValidKey.to_errno()
	};
	check!(colon == b':', Error::InvalidData);

	// Check key slice length
	let key_slice = key.as_slice_mut();
	check!(key_slice.len() >= key_data.len(), Error::ApiMisuse);

	// Decode key and adjust slice
	key_slice[..key_data.len()].copy_from_slice(key_data);
	key.data_len = key_data.len();
	0
}