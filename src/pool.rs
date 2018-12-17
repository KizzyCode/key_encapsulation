use crate::{Error, PluginError, Capsule, plugin::{ Plugin, CSlice, CSliceMut } };
use ::{ asn1_der::DerObject, std::{ path::Path, collections::HashMap, ffi::{ CStr, CString } } };


/// A plugin-pool that manages the loading and the "capsule format UID" <-> plugin relationship
pub struct Pool {
	plugins: HashMap<String, Plugin>
}
impl Pool {
	/// Creates a new plugin pool
	pub fn new() -> Self {
		Self{ plugins: HashMap::new() }
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
		let capsule_format_uid = unsafe{ CStr::from_ptr((plugin.capsule_format_uid)()) }
			.to_str().unwrap().to_string();
		
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
	pub fn capsule_keys(&self, capsule_format_uid: &ToString) -> Result<Vec<String>, Error> {
		// Get plugin
		let plugin = self.plugin(capsule_format_uid)?;
		
		// Allocate a buffer for the capsule key IDs and get them
		let mut buf = vec![0u8; Self::buf_max_len(plugin, b"capsule_key_ids\0")];
		let mut buf = CSliceMut::with(&mut buf);
		PluginError::check_errno(unsafe{ (plugin.capsule_key_ids)(&mut buf) })?;
		
		// Parse the IDs
		let (mut ids, mut pos) = (Vec::new(), 0);
		while pos < buf.data_len {
			let id = unsafe{ CStr::from_ptr(buf.data.offset(pos as _) as _) };
			pos += id.to_bytes_with_nul().len();
			ids.push(id.to_str().unwrap().to_owned());
		}
		Ok(ids)
	}
	
	
	/// Predicts the *maximum* length for a key capsule
	pub fn sealed_max_len(&self, capsule_format_uid: &ToString) -> Result<usize, Error> {
		let payload_max_len =
			Self::buf_max_len(self.plugin(capsule_format_uid)?, b"seal_key\0");
		Ok(Capsule::compute_serialized_len(capsule_format_uid, payload_max_len))
	}
	/// Seals `key`
	///
	/// Arguments:
	///  - `key`: The key-bytes to seal
	///  - `capsule_format_uid`: The capsule format to use (a plugin that implements this format
	///    must be loaded)
	///  - `capsule_key_id`: The ID of the capsule key to use
	///  - `auth_info`: An authentication info (e.g. PIN/password etc.) passed to the plugin
	pub fn seal<'a>(&self, key: &[u8], capsule_format_uid: &ToString,
		capsule_key_id: impl AsRef<str>, auth_info: &[u8]) -> Result<Capsule, Error>
	{
		// Load the corresponding plugin and create a buffer
		let plugin = self.plugin(capsule_format_uid)?;
		let mut tag = 0u8;
		let mut payload = vec![0u8; Self::buf_max_len(plugin, b"seal_key\0")];
		
		// Seal the key
		let payload_len = {
			// Create the slice and a CString for the capsule key ID
			let mut payload_slice = CSliceMut::with(&mut payload);
			let capsule_key_id = CString::new(capsule_key_id.as_ref())
				.map_err(|_| Error::ApiMisuse)?;
			
			// Call the library
			PluginError::check_errno(unsafe{ (plugin.seal_key)(
				&mut tag, &mut payload_slice, &CSlice::with(key),
				capsule_key_id.as_ptr(), &CSlice::with(auth_info)
			) })?;
			payload_slice.data_len
		};
		payload.truncate(payload_len);
		
		// Create capsule
		let plugin_payload = DerObject::new(tag.into(), payload.into());
		Ok(Capsule::new(capsule_format_uid, plugin_payload))
	}
	
	
	/// Predicts the *maximum* length for an opened key
	pub fn opened_max_len(&self, capsule_format_uid: &ToString) -> Result<usize, Error>	{
		Ok(Self::buf_max_len(self.plugin(capsule_format_uid)?, b"open_capsule\0"))
	}
	/// Opens `capsule`
	///
	/// Arguments:
	///  - `key`: The buffer to write the unsealed key to
	///  - `capsule`: The capsule to open
	///  - `auth_info`: An authentication info (e.g. PIN/password etc.) passed to the plugin
	pub fn open<'a>(&self, key: &mut[u8], capsule: &Capsule, auth_info: &[u8])
		-> Result<usize, Error>
	{
		// Load the corresponding plugin
		let plugin = self.plugin(&capsule.capsule_format_uid)?;
		
		// Create a buffer and open the plugin
		let mut key_slice = CSliceMut::with(key);
		PluginError::check_errno(unsafe{ (plugin.open_capsule)(
			&mut key_slice, capsule.plugin_payload.tag.into(),
			&CSlice::with(&capsule.plugin_payload.value.data), &CSlice::with(auth_info)
		) })?;
		
		Ok(key_slice.data_len)
	}
	
	
	/// Gets a reference to a loaded plugin or returns an `KeyEncapsulationError::ApiMisuse` error
	fn plugin(&self, capsule_format_uid: &ToString) -> Result<&Plugin, Error> {
		self.plugins.get(&capsule_format_uid.to_string())
			.ok_or(Error::ApiMisuse)
	}
	/// The *maximum* length a buffer will need to store all data for produced by `fn_name`
	fn buf_max_len(plugin: &Plugin, fn_name: &[u8]) -> usize {
		unsafe{ (plugin.buf_len_max)(fn_name.as_ptr() as _) }
	}
}