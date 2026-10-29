//! # allocator infrastructure
//!
//! The public interface allows setting a custom allocator, but we need to configure a default
//! allocator if the user did not configure one. We have two choices, configured by feature flags:
//!
//! - `"rust-allocator"` uses the rust global allocator
//! - `"c-allocator"` uses an allocator based on `malloc` and `free`
//!
//! When both configured, `"rust-allocator"` is preferred.
//!
//! The interface for the allocator is not a great fit for rust. In particular, rust always needs
//! the layout of an allocation to deallocate it, and C interfaces don't usually provide this
//! information. Luckily in the library we know in all cases how big the allocation was at the
//! point where we deallocate it.

#[cfg(feature = "rust-allocator")]
extern crate alloc;

use core::alloc::{AllocError, Allocator, Layout};
use core::ffi::{c_int, c_void};
use core::ptr::NonNull;

#[derive(Clone, Copy)]
pub(crate) struct CustomAllocator {
    allocator: AllocFunc,
    deallocate: FreeFunc,
    opaque: *mut c_void,
}

impl CustomAllocator {
    /// # Safety
    ///
    /// - `allocate` and `opaque` must form a valid allocator, meaning `allocate` returns either
    ///     * a `NULL` pointer
    ///     * a valid pointer to an allocation of `len * size_of::<T>()` bytes aligned to at least `align_of::<usize>()`
    /// - `deallocate` frees memory allocated by `allocate`
    pub(crate) fn new(allocator: AllocFunc, deallocate: FreeFunc, opaque: *mut c_void) -> Self {
        Self {
            allocator,
            deallocate,
            opaque,
        }
    }
}

unsafe impl Allocator for CustomAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        match layout.size() {
            0 => Ok(layout.dangling_ptr().cast_slice(0)),
            // SAFETY: `layout` is non-zero in size
            size => {
                // Ensure that we're not going to underallocate
                let Ok(malloc_size) = i32::try_from(size) else {
                    return Err(AllocError);
                };
                // We ignore the alignment here and hope that our alignment is low enough
                // that any malloc implementation will satisfy it
                let raw_ptr = unsafe { (self.allocator)(self.opaque, 1, malloc_size) };
                // Make sure that the alignment requirement is met
                // FIXME: Use ptr::is_aligned_to once stable
                assert!(raw_ptr.addr().is_multiple_of(layout.align()));
                let ptr = NonNull::new(raw_ptr.cast()).ok_or(AllocError)?;

                Ok(ptr.cast_slice(size))
            }
        }
    }

    fn allocate_zeroed(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        match layout.size() {
            0 => Ok(layout.dangling_ptr().cast_slice(0)),
            // SAFETY: `layout` is non-zero in size
            size => {
                let ptr = self.allocate(layout)?;

                // Zero-initialize it
                unsafe { core::ptr::write_bytes(ptr.as_ptr().cast::<u8>(), 0, size) };

                Ok(ptr)
            }
        }
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        if layout.size() != 0 {
            // SAFETY: `layout` is non-zero in size
            // other conditions must be upheld by the caller
            unsafe { (self.deallocate)(self.opaque, ptr.as_ptr().cast()) };
        }
    }
}

type AllocFunc = unsafe extern "C" fn(*mut c_void, c_int, c_int) -> *mut c_void;
type FreeFunc = unsafe extern "C" fn(*mut c_void, *mut c_void) -> ();

#[derive(Clone, Copy)]
pub(crate) enum BzipAllocator {
    #[cfg(feature = "rust-allocator")]
    Rust(alloc::alloc::Global),
    // FIXME: Ideally System would be in alloc
    #[cfg(all(feature = "c-allocator", not(feature = "rust-allocator")))]
    C(std::alloc::System),
    Custom(CustomAllocator),
}

impl BzipAllocator {
    #[cfg(feature = "rust-allocator")]
    pub(crate) const DEFAULT: Option<Self> = Some(Self::Rust(alloc::alloc::Global));

    #[cfg(all(feature = "c-allocator", not(feature = "rust-allocator")))]
    pub(crate) const DEFAULT: Option<Self> = Some(Self::C(std::alloc::System));

    #[cfg(not(any(feature = "rust-allocator", feature = "c-allocator")))]
    pub(crate) const DEFAULT: Option<Self> = None;
}

unsafe impl Allocator for BzipAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        match self {
            Self::Custom(a) => a.allocate(layout),
            #[cfg(feature = "rust-allocator")]
            Self::Rust(a) => a.allocate(layout),
            #[cfg(all(feature = "c-allocator", not(feature = "rust-allocator")))]
            Self::C(a) => a.allocate(layout),
        }
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        match self {
            Self::Custom(a) => unsafe { a.deallocate(ptr, layout) },
            #[cfg(feature = "rust-allocator")]
            Self::Rust(a) => unsafe { a.deallocate(ptr, layout) },
            #[cfg(all(feature = "c-allocator", not(feature = "rust-allocator")))]
            Self::C(a) => unsafe { a.deallocate(ptr, layout) },
        }
    }

    fn allocate_zeroed(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        match self {
            Self::Custom(a) => a.allocate_zeroed(layout),
            #[cfg(feature = "rust-allocator")]
            Self::Rust(a) => a.allocate_zeroed(layout),
            #[cfg(all(feature = "c-allocator", not(feature = "rust-allocator")))]
            Self::C(a) => a.allocate_zeroed(layout),
        }
    }

    unsafe fn grow(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        match self {
            Self::Custom(a) => unsafe { a.grow(ptr, old_layout, new_layout) },
            #[cfg(feature = "rust-allocator")]
            Self::Rust(a) => unsafe { a.grow(ptr, old_layout, new_layout) },
            #[cfg(all(feature = "c-allocator", not(feature = "rust-allocator")))]
            Self::C(a) => unsafe { a.grow(ptr, old_layout, new_layout) },
        }
    }

    unsafe fn grow_zeroed(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        match self {
            Self::Custom(a) => unsafe { a.grow_zeroed(ptr, old_layout, new_layout) },
            #[cfg(feature = "rust-allocator")]
            Self::Rust(a) => unsafe { a.grow_zeroed(ptr, old_layout, new_layout) },
            #[cfg(all(feature = "c-allocator", not(feature = "rust-allocator")))]
            Self::C(a) => unsafe { a.grow_zeroed(ptr, old_layout, new_layout) },
        }
    }

    unsafe fn shrink(
        &self,
        ptr: NonNull<u8>,
        old_layout: Layout,
        new_layout: Layout,
    ) -> Result<NonNull<[u8]>, AllocError> {
        match self {
            Self::Custom(a) => unsafe { a.shrink(ptr, old_layout, new_layout) },
            #[cfg(feature = "rust-allocator")]
            Self::Rust(a) => unsafe { a.shrink(ptr, old_layout, new_layout) },
            #[cfg(all(feature = "c-allocator", not(feature = "rust-allocator")))]
            Self::C(a) => unsafe { a.shrink(ptr, old_layout, new_layout) },
        }
    }
}
