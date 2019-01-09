use crate::{ Error, PluginErrorType, ffi::FromCStr };
use std::u64;


const ENONE: [u8; 16] = *b"ENONE\0\0\0\0\0\0\0\0\0\0\0";
const EINIT: [u8; 16] = *b"EINIT\0\0\0\0\0\0\0\0\0\0\0";
const EPERM: [u8; 16] = *b"EPERM\0\0\0\0\0\0\0\0\0\0\0";
const EACCESS: [u8; 16] = *b"EACCESS\0\0\0\0\0\0\0\0\0";
const EIO: [u8; 16] = *b"EIO\0\0\0\0\0\0\0\0\0\0\0\0\0";
const EILSEQ: [u8; 16] = *b"EILSEQ\0\0\0\0\0\0\0\0\0\0";
const ENOKEY: [u8; 16] = *b"ENOKEY\0\0\0\0\0\0\0\0\0\0";
const ECANCELED: [u8; 16] = *b"ECANCELED\0\0\0\0\0\0\0";
const ETIMEDOUT: [u8; 16] = *b"ETIMEDOUT\0\0\0\0\0\0\0";
const EINVAL: [u8; 16] = *b"EINVAL\0\0\0\0\0\0\0\0\0\0";
const EOTHER: [u8; 16] = *b"EOTHER\0\0\0\0\0\0\0\0\0\0";


/// An `error_t` implementation
#[repr(C)] #[derive(Copy, Clone)]
pub struct CError {
	pub type_id: [u8; 16],
	
	pub file: [u8; 256],
	pub line: u32,
	pub description: [u8; 1024],
	
	pub info: u64
}
impl CError {
	/// Checks if the `CError` is an error and converts it accordingly
	pub fn check(self) -> Result<(), Error> {
		// Match the error type
		let error_type = match self.type_id {
			ENONE => return Ok(()),
			EINIT => PluginErrorType::EInit,
			EPERM => PluginErrorType::EPerm{ requires_authentication: self.info != 0 },
			EACCESS => PluginErrorType::EAccess {
				retries_left: match self.info {
					u64::MAX => None,
					retries_left => Some(retries_left)
				}
			},
			EIO => PluginErrorType::EIO,
			EILSEQ => PluginErrorType::EIlSeq,
			ENOKEY => PluginErrorType::ENoKey,
			ECANCELED => PluginErrorType::ECancelled,
			ETIMEDOUT => PluginErrorType::ETimedOut,
			EINVAL => PluginErrorType::EInval{ argument_index: self.info },
			EOTHER => PluginErrorType::EOther{ code: self.info },
			_ => panic!("Plugin API violation")
		};
		
		// Convert strings
		Err(Error::PluginError{
			file: String::from_c_str(&self.file),
			line: self.line,
			description: String::from_c_str(&self.description),
			error_type
		})
	}
}