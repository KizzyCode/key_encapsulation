use crate::Error;
use ::{
	asn1_der::{ IntoDerObject, FromDerObject, DerObject, U128Ext },
	std::{ io::ErrorKind as IoErrorKind }
};


/// A key capsule
#[derive(Asn1Der)]
pub struct Capsule {
	version: u128,
	pub(in crate) capsule_format_uid: String,
	pub(in crate) plugin_payload: DerObject
}
impl Capsule {
	/// Creates a new v1 key capsule with `capsule_format_uid` and `plugin_payload`
	pub(in crate) fn new(capsule_format_uid: &ToString, plugin_payload: DerObject) -> Self {
		Self{ version: 1, capsule_format_uid: capsule_format_uid.to_string(), plugin_payload }
	}
	/// Parses a v1 key capsule from `data`
	pub fn parse<'a>(data: impl Iterator<Item = &'a u8>) -> Result<Self, Error> {
		// Parse generic sequence
		let mut generic = Vec::<DerObject>::deserialize(data)?;
		check!(!generic.is_empty(), IoErrorKind::InvalidData);
		
		// Validate version
		let version: u128 = u128::from_der_object(generic.remove(0))?;
		check!(version.u8()? == 1, Error::Unsupported);
		
		// Parse struct
		check!(generic.len() == 2, IoErrorKind::InvalidData);
		Ok(Self {
			version,
			capsule_format_uid: String::from_der_object(generic.remove(0))?,
			plugin_payload: generic.remove(0)
		})
	}
	/// Serializes the key capsule into `buf` and returns the amount of bytes written into `buf`
	pub fn serialize<'a>(self, buf: impl Iterator<Item = &'a mut u8>) -> Result<usize, Error> {
		Ok(IntoDerObject::serialize(self, buf)?)
	}
	/// The serialized length of the key capsule
	pub fn serialized_len(&self) -> usize {
		IntoDerObject::serialized_len(self)
	}
	
	
	/// Computes the serialized length of the entire capsule for a plugin's DER-*payload* length
	pub(in crate) fn compute_serialized_len(capsule_format_uid: &ToString,
		plugin_payload_len: usize) -> usize
	{
		let sequence_payload_len = 1u128.serialized_len()
			+ capsule_format_uid.to_string().serialized_len()
			+ DerObject::compute_serialized_len(plugin_payload_len);
		DerObject::compute_serialized_len(sequence_payload_len)
	}
}