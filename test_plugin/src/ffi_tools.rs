use ::std::{ marker::PhantomData, slice };


pub trait CheckedDeref<'a, T: 'a>: Copy + 'a {
	fn checked_deref(self) -> &'a T;
}
impl<'a, T: 'a> CheckedDeref<'a, T> for *const T {
	fn checked_deref(self) -> &'a T {
		assert!(!self.is_null());
		unsafe{ &*self }
	}
}

pub trait CheckedDerefMut<'a, T: 'a>: Copy + 'a {
	fn checked_deref_mut(self) -> &'a mut T;
}
impl<'a, T: 'a> CheckedDerefMut<'a, T> for *mut T {
	fn checked_deref_mut(self) -> &'a mut T {
		assert!(!self.is_null());
		unsafe{ &mut *self }
	}
}


#[repr(C)]
pub struct CSlice<'a> {
	pub data: *const u8,
	pub data_len: usize,
	_lifetime: PhantomData<&'a[u8]>
}
impl<'a> CSlice<'a> {
	pub fn as_slice(&self) -> &'a[u8] {
		unsafe{ slice::from_raw_parts(self.data, self.data_len) }
	}
}

#[repr(C)]
pub struct CSliceMut<'a> {
	pub data: *mut u8,
	pub data_len: usize,
	_lifetime: PhantomData<&'a[u8]>
}
impl<'a> CSliceMut<'a> {
	pub fn as_slice_mut(&self) -> &'a mut[u8] {
		unsafe{ slice::from_raw_parts_mut(self.data, self.data_len) }
	}
}