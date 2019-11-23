use kync::{
	Plugin,
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


const FORMAT_UID: &[u8] = b"TestCapsuleFormat.3A0351A7-FE90-4383-9E68-FCC20033D5F1";
const USER_SECRET: Option<&[u8]> = Some(b"Testolope");
const KEY: &[u8] = b"2nwBK-EkfXW-yWSQv-Vkab3-USHvX-WNJxa-GeXFJ-ecsjJ-imnft";
const PAYLOAD: &[u8] = b"tfnmi-Jjsce-JFXeG-axJNW-XvHSU-3bakV-vQSWy-WXfkE-KBwn2";


#[test]
fn test() {
	// Load plugin and test format UID
	let plugin = load_plugin();
	assert_eq!(plugin.id().unwrap(), FORMAT_UID);
	
	// Get the first config
	let configs = plugin.configs().unwrap();
	assert_eq!(&configs[0], b"Default");
	
	// Protect a key with config 0
	let protected = plugin.protect(KEY, &configs[0], USER_SECRET).unwrap();
	assert_eq!(protected, PAYLOAD);
	
	// Recover a key
	let recovered = plugin.recover(&protected, USER_SECRET).unwrap();
	assert_eq!(recovered, KEY);
}