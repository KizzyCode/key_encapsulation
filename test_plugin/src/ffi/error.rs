/// A representation of an `error_t`-type-ID
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ErrorType {
	ENone, EInit, EPerm, EAccess, EIO, EIlSeq, ENoKey, ECanceled, ETimedout, EInval, EOther
}
impl ErrorType {
	pub fn as_raw(self) -> [u8; 16] {
		*match self {
			ErrorType::ENone => b"ENONE\0\0\0\0\0\0\0\0\0\0\0",
			ErrorType::EInit => b"EINIT\0\0\0\0\0\0\0\0\0\0\0",
			ErrorType::EPerm => b"EPERM\0\0\0\0\0\0\0\0\0\0\0",
			ErrorType::EAccess => b"EACCESS\0\0\0\0\0\0\0\0\0",
			ErrorType::EIO => b"EIO\0\0\0\0\0\0\0\0\0\0\0\0\0",
			ErrorType::EIlSeq => b"EILSEQ\0\0\0\0\0\0\0\0\0\0",
			ErrorType::ENoKey => b"ENOKEY\0\0\0\0\0\0\0\0\0\0",
			ErrorType::ECanceled => b"ECANCELED\0\0\0\0\0\0\0",
			ErrorType::ETimedout => b"ETIMEDOUT\0\0\0\0\0\0\0",
			ErrorType::EInval => b"EINVAL\0\0\0\0\0\0\0\0\0\0",
			ErrorType::EOther => b"EOTHER\0\0\0\0\0\0\0\0\0\0"
		}
	}
}


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
	/// Creates a new `error_t`
	pub fn new(type_id: ErrorType, file: impl AsRef<str>, line: u32, description: impl AsRef<str>,
		info: u64) -> Self
	{
		macro_rules! str_to_array {
			($str:expr => [$len:expr]) => ({
				assert!($str.len() <= $len, "`$str` does not fit into the array");
				
				let mut array: [u8; $len] = [0; $len];
				array[..$str.len()].copy_from_slice($str.as_bytes());
				array
			});
		}
		
		CError {
			type_id: type_id.as_raw(),
			
			file: str_to_array!(file.as_ref() => [256]), line,
			description: str_to_array!(description.as_ref() => [1024]),
			
			info
		}
	}
}


/// Creates and returns a new `CError`/`error_t`
#[macro_export]
macro_rules! err {
	($type_id:expr, $description:expr, $info:expr) => ({
		return CError::new($type_id, file!(), line!(), $description, $info)
	})
}
/// Creates and returns an `ENONE` `CError`/`error_t`
#[macro_export]
macro_rules! ok {
	() => ({
		use crate::ffi::ErrorType;
		err!(ErrorType::ENone, "Nothing happened; everything is ok :)", 0)
	});
}