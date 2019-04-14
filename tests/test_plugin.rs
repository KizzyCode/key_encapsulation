use kync::{
	ErrorKind, Plugin,
	plugin::{ os_default_prefix, os_default_suffix }
};
use std::path::PathBuf;

/// Load the test plugin
fn load_plugin() -> Plugin {
	// Create path
	let mut path = PathBuf::new();
	path.push("target");
	path.push(if cfg!(debug_assertions) { "debug" } else { "release" });
	path.push("deps");
	path.push(format!("{}kync_test_plugin.{}", os_default_prefix(), os_default_suffix()));
	
	// Load plugin
	Plugin::load(path).unwrap()
}


const FORMAT_UID: &str = "TestCapsuleFormat.3A0351A7-FE90-4383-9E68-FCC20033D5F1";
const USER_SECRET: Option<&[u8]> = Some(b"Testolope");
const KEY: &[u8] = b"2nwBK-EkfXW-yWSQv-Vkab3-USHvX-WNJxa-GeXFJ-ecsjJ-imnft";
const PAYLOAD: &[u8] = b"tfnmi-Jjsce-JFXeG-axJNW-XvHSU-3bakV-vQSWy-WXfkE-KBwn2";


#[test]
fn test() {
	// Load plugin
	let plugin = load_plugin();
	
	// Test format UID
	assert_eq!(plugin.capsule_format_uid(), FORMAT_UID);
	
	// Seal a key
	let mut buf: Vec<u8> = vec![0; plugin.seal_buf_len(KEY.len())];
	let len = plugin.seal(
		&mut buf, KEY,
		None as Option<&[u8]>, USER_SECRET
	).unwrap();
	
	assert_eq!(&buf[..len], PAYLOAD);
	
	// Open a key
	let mut buf = vec![0; plugin.open_buf_len(KEY.len())];
	let len =
		plugin.open(&mut buf, PAYLOAD, USER_SECRET).unwrap();
	
	assert_eq!(&buf[..len], KEY);
}


#[test]
fn test_auth_errors() {
	// Load pool
	let plugin = load_plugin();
	
	// Sealing
	let mut buf: Vec<u8> = vec![0; plugin.seal_buf_len(KEY.len())];
	let err = plugin.seal(
		&mut buf, KEY,
		None as Option<&[u8]>, None as Option<&[u8]>
	).unwrap_err();
	
	assert_eq!(err.kind, ErrorKind::PermissionDenied{ requires_authentication: true });
	
	// Opening
	let mut buf: Vec<u8> = vec![0; plugin.open_buf_len(KEY.len())];
	let err = plugin.open(
		&mut buf, PAYLOAD,
		None as Option<&[u8]>
	).unwrap_err();
	
	assert_eq!(err.kind, ErrorKind::PermissionDenied{ requires_authentication: true });
}