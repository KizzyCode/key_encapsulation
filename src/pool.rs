use crate::{Error, Capsule, plugin::Plugin, ffi::FromCStr };
use ::{ asn1_der::DerObject, std::{ path::Path, collections::HashMap } };


/// A plugin-pool that manages the loading and the "capsule format UID" <-> plugin relationship
pub struct Pool {
	plugins: HashMap<String, Plugin>
}
impl Pool {
	/// Creates a new plugin pool
	pub fn new() -> Self {
		Self{ plugins: HashMap::new() }
	}
	
	/// Creates a new plugin pool and loads the plugin at `path`
	pub fn with_plugin(path: impl AsRef<Path>) -> Result<Self, Error> {
		let mut pool = Pool::new();
		pool.load(path)?;
		Ok(pool)
	}
	
	/// Creates a new plugin pool and loads the plugins in `paths`
	pub fn with_plugins<'a>(paths: impl Iterator<Item = &'a (impl AsRef<Path> + 'a)>)
		-> Result<Self, Error>
	{
		let mut pool = Pool::new();
		for path in paths { pool.load(path)?; }
		Ok(pool)
	}
	
	
	/// Loads the plugin stored at `path` into the pool
	pub fn load<T: AsRef<Path>>(&mut self, path: T) -> Result<&mut Self, Error> {
		// Load plugin
		let plugin = Plugin::load(path)?;
		let c_str = plugin.capsule_format_uid();
		let capsule_format_uid = String::from_c_str(c_str);
		
		// Ensure that we don't already have a plugin with this format UID and store the plugin
		check!(!self.plugins.contains_key(&capsule_format_uid), Error::ApiMisuse);
		self.plugins.insert(capsule_format_uid, plugin);
		Ok(self)
	}
	
	
	/// The available capsule format UIDs that have a plugin loaded
	pub fn capsule_format_uids(&self) -> Vec<String> {
		self.plugins.keys().map(|k| k.to_owned()).collect()
	}
	
	/// The available capsule keys for a capsule format (or rather the capsule key IDs offered by
	/// the loaded plugin that implements this format)
	pub fn capsule_key_ids(&self, capsule_format_uid: impl ToString) -> Result<Vec<String>, Error> {
		// Load the corresponding plugin and create a buffer
		let plugin = self.plugin(&capsule_format_uid)?;
		let mut buf = vec![0; plugin.buf_len_max("capsule_key_ids")];
		let buf_len = plugin.capsule_key_ids(&mut buf)?;
		
		// Check buffer length and truncate buffer
		assert_eq!(buf_len % 256, 0, "Plugin API violation");
		buf.truncate(buf_len);
		
		// Parse the IDs
		let mut ids = Vec::new();
		for i in (0..buf.len()).step_by(256) {
			let id = String::from_c_str(&buf[i .. i + 256]);
			ids.push(id);
		}
		Ok(ids)
	}
	
	
	/// Predicts the *maximum* length for a key capsule
	pub fn sealed_max_len(&self, capsule_format_uid: impl ToString) -> Result<usize, Error> {
		let plugin_payload_len = self.plugin(&capsule_format_uid)?
			.buf_len_max("seal");
		Ok(Capsule::compute_serialized_len(capsule_format_uid, plugin_payload_len))
	}
	
	/// Seals `key`
	///
	/// Arguments:
	///  - `key`: The key-bytes to seal
	///  - `capsule_format_uid`: The capsule format to use (a plugin that implements this format
	///    must be loaded)
	///  - `capsule_key_id`: The ID of the capsule key to use
	///  - `user_secret`: An authentication info/user secret (e.g. PIN/password etc.) passed to the
	///    plugin
	pub fn seal<'a>(&self, key: &[u8], capsule_format_uid: impl ToString,
		capsule_key_id: Option<&str>, user_secret: Option<&[u8]>) -> Result<Capsule, Error>
	{
		// Load the corresponding plugin and create a buffer
		let plugin = self.plugin(&capsule_format_uid)?;
		let mut der_tag = 0u8;
		let mut der_payload = vec![0u8; plugin.buf_len_max("seal")];
		
		// Seal the key and create the capsule
		let der_payload_len = plugin.seal(
			&mut der_tag, &mut der_payload, key,
			capsule_key_id, user_secret
		)?;
		der_payload.truncate(der_payload_len);
		
		Ok(Capsule::new(
			capsule_format_uid,
			DerObject::new(der_tag.into(), der_payload.into())
		))
	}
	
	
	/// Predicts the *maximum* length for an opened key
	pub fn opened_max_len(&self, capsule_format_uid: impl ToString) -> Result<usize, Error>	{
		Ok(self.plugin(&capsule_format_uid)?.buf_len_max("open"))
	}
	
	/// Opens `capsule`
	///
	/// Arguments:
	///  - `key`: The buffer to write the unsealed key to
	///  - `capsule`: The capsule to open
	///  - `user_secret`: An authentication info (e.g. PIN/password etc.) passed to the plugin
	pub fn open<'a>(&self, key: &mut[u8], capsule: &Capsule, user_secret: Option<&[u8]>)
		-> Result<usize, Error>
	{
		// Load the corresponding plugin and alias the DER-object
		let plugin = self.plugin(&capsule.capsule_format_uid)?;
		let der = &capsule.plugin_payload;
		
		// Open the capsule
		plugin.open(key, der.tag.into(), &der.value.data, user_secret)
	}
	
	
	/// Gets a reference to a loaded plugin or returns an `KeyEncapsulationError::ApiMisuse` error
	fn plugin(&self, capsule_format_uid: &ToString) -> Result<&Plugin, Error> {
		self.plugins.get(&capsule_format_uid.to_string()).ok_or(Error::ApiMisuse)
	}
}