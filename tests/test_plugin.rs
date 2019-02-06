use kync::{ ErrorKind, Plugin };
use std::path::PathBuf;

/// Load the test plugin
fn load_plugin() -> Plugin {
	// Create base path
	let mut path = match cfg!(debug_assertions) {
		true => PathBuf::from("target/debug/deps".to_string()),
		false => PathBuf::from("target/release/deps".to_string())
	};
	
	// Append library name
	match true {
		_ if cfg!(target_os = "windows") => path.push("test_plugin.dll"),
		_ if cfg!(target_os = "macos") => path.push("libtest_plugin.dylib"),
		_ if cfg!(target_family = "unix") => path.push("libtest_plugin.so"),
		_ => unimplemented!("Your current platform has no test yet")
	};
	
	// Load plugin
	Plugin::load(path).unwrap()
}


const CAPSULE_FORMAT_UID: &[u8] =
	b"TestCapsuleFormat__________.3A0351A7-FE90-4383-9E68-FCC20033D5F1";
const TEST_USER_SECRET: Option<&[u8]> = Some(b"Testolope");
const KEY: &[u8] = b"2nwBK-EkfXW-yWSQv-Vkab3-USHvX-WNJxa-GeXFJ-ecsjJ-imnft";
const PAYLOAD: &[u8] = b"tfnmi-Jjsce-JFXeG-axJNW-XvHSU-3bakV-vQSWy-WXfkE-KBwn2";


#[test]
fn test() {
	// Load plugin
	let plugin = load_plugin();
	
	// Test format UID
	assert_eq!(plugin.capsule_format_uid(), CAPSULE_FORMAT_UID);
	
	// Seal a key
	let mut buf: Vec<u8> = Vec::new();
	let len = plugin.seal(
		&mut buf, KEY,
		None as Option<&[u8]>, TEST_USER_SECRET
	).unwrap();
	
	assert_eq!(&buf[..len], PAYLOAD);
	
	// Open a key
	let mut buf = Vec::new();
	let len =
		plugin.open(&mut buf, PAYLOAD, TEST_USER_SECRET).unwrap();
	
	assert_eq!(&buf[..len], KEY);
}


#[test]
fn test_auth_errors() {
	// Load pool
	let plugin = load_plugin();
	
	// Sealing
	let err = plugin.seal(
		&mut Vec::new(), KEY,
		None as Option<&[u8]>, None as Option<&[u8]>
	).unwrap_err();
	assert_eq!(err.kind, ErrorKind::PermissionDenied{ requires_authentication: true });
	
	// Opening
	let err = plugin.open(
		&mut Vec::new(), PAYLOAD,
		None as Option<&[u8]>
	).unwrap_err();
	assert_eq!(err.kind, ErrorKind::PermissionDenied{ requires_authentication: true });
}