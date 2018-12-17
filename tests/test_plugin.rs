use key_encapsulation::{ Capsule, Pool };
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
		_ if cfg!(target_os = "windows") => path.push("libtest_plugin.dll"),
		_ if cfg!(target_os = "macos") => path.push("libtest_plugin.dylib"),
		_ if cfg!(target_os = "unix") => path.push("libtest_plugin.so"),
		_ => unimplemented!("Your current platform has no test yet")
	};
	
	// Load plugin
	Pool::with_plugin(path).unwrap()
}


const CAPSULE_FORMAT_UID: &str = "TestCapsuleFormat.3A0351A7-FE90-4383-9E68-FCC20033D5F1";
const KEY: &[u8] = b"2nwBK-EkfXW-yWSQv-Vkab3-USHvX-WNJxa-GeXFJ-ecsjJ-imnft";
const CAPSULE: &[u8] = include_bytes!("capsule");


#[test]
fn test() {
	// Load pool
	let pool = create_pool();
	
	// Test format UID
	assert_eq!(pool.capsule_format_uids(), vec![CAPSULE_FORMAT_UID.to_string()]);
	
	// Test capsule key IDs
	assert_eq!(
		pool.capsule_keys(CAPSULE_FORMAT_UID).unwrap(),
		vec!["Key0".to_string(), "Key1".to_string(), "Key7".to_string()]
	);
	
	// Sealed and opened max length
	assert_eq!(pool.sealed_max_len(CAPSULE_FORMAT_UID).unwrap(), 1091);
	assert_eq!(pool.opened_max_len(CAPSULE_FORMAT_UID).unwrap(), 1024);
	
	
	// Seal a key
	let mut capsule_buf = [0u8; 1091];
	let capsule = pool
		.seal(KEY, CAPSULE_FORMAT_UID, "Key0", b"Key0")
		.unwrap();
	let capsule_len = capsule.serialize(capsule_buf.iter_mut()).unwrap();
	
	assert_eq!(&capsule_buf[..capsule_len], CAPSULE);
	
	
	// Open a key
	let mut key_buf = [0u8; 1024];
	let capsule = Capsule::parse(CAPSULE.iter()).unwrap();
	let key_len = pool.open(&mut key_buf, &capsule, b"Key0").unwrap();
	
	assert_eq!(&key_buf[..key_len], KEY);
}