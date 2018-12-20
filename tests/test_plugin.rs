use kync::{ Error, PluginError, Capsule, Pool };
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
const KEY: &[u8] = b"2nwBK-EkfXW-yWSQv-Vkab3-USHvX-WNJxa-GeXFJ-ecsjJ-imnft";
const CAPSULE: &[u8] = include_bytes!("capsule.bin");


#[test]
fn test() {
	// Load pool
	let pool = create_pool();
	
	// Test format UID
	assert_eq!(pool.capsule_format_uids(), vec![CAPSULE_FORMAT_UID.to_string()]);
	
	// Test capsule.bin key IDs
	assert_eq!(
		pool.capsule_keys(CAPSULE_FORMAT_UID).unwrap(),
		vec!["Key0".to_string(), "Key1".to_string(), "Key7".to_string()]
	);
	
	// Sealed and opened max length
	assert_eq!(pool.sealed_max_len(CAPSULE_FORMAT_UID).unwrap(), 1117);
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


#[test]
fn test_invalid_capsule_format_uids() {
	// Load pool
	let pool = create_pool();
	
	// Test invalid capsule format UIDs
	assert_eq!(pool.capsule_keys("Invalid .)"), Err(Error::ApiMisuse));
	assert_eq!(pool.sealed_max_len("Invalid .)"), Err(Error::ApiMisuse));
	assert_eq!(pool.opened_max_len("Invalid .)"), Err(Error::ApiMisuse));
	
	assert_eq!(
		pool.seal(KEY, ".)", "", b""),
		Err(Error::ApiMisuse)
	);
}


#[test]
fn test_invalid_key_ids() {
	// Load pool
	let pool = create_pool();
	
	// Sealing
	assert_eq!(
		pool.seal(KEY, CAPSULE_FORMAT_UID, ".)", b""),
		Err(Error::PluginError(PluginError::ApiMisuse))
	);
	
	// Opening
	let mut data = CAPSULE.to_vec();
	data[93] = b'4'; // Modify "Key0" to "Key4"
	
	let capsule = Capsule::parse(data.iter()).unwrap();
	assert_eq!(
		pool.open(&mut[], &capsule, b""),
		Err(Error::PluginError(PluginError::NoValidKey))
	);
}

#[test]
fn test_auth_errors() {
	// Load pool
	let pool = create_pool();
	
	// Sealing
	assert_eq!(
		pool.seal(KEY, CAPSULE_FORMAT_UID, "Key0", b""),
		Err(Error::PluginError(PluginError::AuthenticationError))
	);
	
	// Opening
	let capsule = Capsule::parse(CAPSULE.iter()).unwrap();
	assert_eq!(
		pool.open(&mut[], &capsule, b"Key1"),
		Err(Error::PluginError(PluginError::AuthenticationError))
	);
}

#[test]
fn test_invalid_capsule() {
	// Load pool
	let pool = create_pool();
	
	// Opening
	let mut data = CAPSULE.to_vec();
	data[94] = b';'; // Modify ":" to ";"
	
	let capsule = Capsule::parse(data.iter()).unwrap();
	assert_eq!(
		pool.open(&mut[], &capsule, b"Key0"),
		Err(Error::PluginError(PluginError::InvalidData))
	);
}