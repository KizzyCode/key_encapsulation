use kync::{ Error, PluginErrorType, Capsule, Pool };
use ::std::path::PathBuf;


/// Create a pool with the loaded test-plugin
fn create_pool() -> Pool {
	// Create a path
	let mut path = PathBuf::new();
	
	// Build dir path
	path.push("target");
	if cfg!(debug_assertions) { path.push("debug") }
		else { path.push("release") }
	path.push("deps");
	
	// Append plugin name
	match true {
		_ if cfg!(target_os = "windows") => path.push("test_plugin.dll"),
		_ if cfg!(target_os = "macos") => path.push("libtest_plugin.dylib"),
		_ if cfg!(target_family = "unix") => path.push("libtest_plugin.so"),
		_ => unimplemented!("Your current platform has no test yet")
	};
	
	// Load plugin
	Pool::with_plugin(path).unwrap()
}


const CAPSULE_FORMAT_UID: &str = "TestCapsuleFormat.3A0351A7-FE90-4383-9E68-FCC20033D5F1";
const TEST_USER_SECRET: Option<&[u8]> = Some(b"Testolope");
const KEY: &[u8] = b"2nwBK-EkfXW-yWSQv-Vkab3-USHvX-WNJxa-GeXFJ-ecsjJ-imnft";
const CAPSULE: &[u8] = b"\x30\x81\x8c\x0c\x1b\x64\x65\x2e\x4b\x69\x7a\x7a\x79\x43\x6f\x64\x65\x2e\x4b\x79\x6e\x63\x2e\x43\x61\x70\x73\x75\x6c\x65\x56\x31\x0c\x36\x54\x65\x73\x74\x43\x61\x70\x73\x75\x6c\x65\x46\x6f\x72\x6d\x61\x74\x2e\x33\x41\x30\x33\x35\x31\x41\x37\x2d\x46\x45\x39\x30\x2d\x34\x33\x38\x33\x2d\x39\x45\x36\x38\x2d\x46\x43\x43\x32\x30\x30\x33\x33\x44\x35\x46\x31\x04\x35\x32\x6e\x77\x42\x4b\x2d\x45\x6b\x66\x58\x57\x2d\x79\x57\x53\x51\x76\x2d\x56\x6b\x61\x62\x33\x2d\x55\x53\x48\x76\x58\x2d\x57\x4e\x4a\x78\x61\x2d\x47\x65\x58\x46\x4a\x2d\x65\x63\x73\x6a\x4a\x2d\x69\x6d\x6e\x66\x74";


#[test]
fn test() {
	// Load pool
	let pool = create_pool();
	
	// Test format UID
	assert_eq!(pool.capsule_format_uids(), vec![CAPSULE_FORMAT_UID.to_string()]);
	
	// Test capsule.bin key IDs
	assert_eq!(
		pool.capsule_key_ids(CAPSULE_FORMAT_UID).unwrap(),
		Vec::<String>::new()
	);
	
	// Sealed and opened max length
	assert_eq!(pool.sealed_max_len(CAPSULE_FORMAT_UID).unwrap(), 1117);
	assert_eq!(pool.opened_max_len(CAPSULE_FORMAT_UID).unwrap(), 1024);
	
	// Seal a key
	let mut capsule_buf = [0; 1117];
	let capsule = pool.seal(
		KEY, CAPSULE_FORMAT_UID,
		None, TEST_USER_SECRET
	).unwrap();
	let capsule_len = capsule.serialize(capsule_buf.iter_mut()).unwrap();
	
	assert_eq!(&capsule_buf[..capsule_len], CAPSULE);
	
	
	// Open a key
	let mut key_buf = [0u8; 1024];
	let capsule = Capsule::parse(CAPSULE.iter()).unwrap();
	let key_len =
		pool.open(&mut key_buf, &capsule, TEST_USER_SECRET).unwrap();
	
	assert_eq!(&key_buf[..key_len], KEY);
}


#[test]
fn test_invalid_capsule_format_uids() {
	// Load pool
	let pool = create_pool();
	
	// Test invalid capsule format UIDs
	assert_eq!(pool.capsule_key_ids("Invalid .)"), Err(Error::ApiMisuse));
	assert_eq!(pool.sealed_max_len("Invalid .)"), Err(Error::ApiMisuse));
	assert_eq!(pool.opened_max_len("Invalid .)"), Err(Error::ApiMisuse));
	
	assert_eq!(
		pool.seal(KEY, ".)", None, None),
		Err(Error::ApiMisuse)
	);
}

#[test]
fn test_auth_errors() {
	// Load pool
	let pool = create_pool();
	
	// Sealing
	let err = pool.seal(
		KEY, CAPSULE_FORMAT_UID,
		None, None
	).unwrap_err();
	match err {
		Error::PluginError{ error_type, .. } =>
			assert_eq!(error_type, PluginErrorType::EPerm{ requires_authentication: true }),
		_ => panic!()
	}
	
	// Opening
	let capsule = Capsule::parse(CAPSULE.iter()).unwrap();
	let err = pool.open(&mut[], &capsule, None).unwrap_err();
	match err {
		Error::PluginError{ error_type, .. } =>
			assert_eq!(error_type, PluginErrorType::EPerm{ requires_authentication: true }),
		_ => panic!()
	}
}