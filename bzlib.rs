use core::ffi::{c_char, c_int, c_uint, c_void, CStr};
use core::{mem, ptr};

use libc::FILE;
use libc::{fclose, fdopen, ferror, fflush, fgetc, fopen, fread, free, fwrite, malloc, ungetc};

use crate::compress::compress_block;
use crate::crctable::BZ2_CRC32TABLE;
use crate::decompress::{self, decompress};
use crate::libbzip2_rs_sys_version;
use crate::BZ_MAX_UNUSED;

pub(crate) const BZ_MAX_ALPHA_SIZE: usize = 258;
pub(crate) const BZ_MAX_CODE_LEN: usize = 23;

pub(crate) const BZ_N_GROUPS: usize = 6;
pub(crate) const BZ_G_SIZE: usize = 50;
pub(crate) const BZ_N_ITERS: usize = 4;

pub(crate) const BZ_MAX_SELECTORS: usize = 2 + (900000 / BZ_G_SIZE);

pub(crate) const BZ_RUNA: u16 = 0;
pub(crate) const BZ_RUNB: u16 = 1;

pub(crate) const BZ_MAX_UNUSED_U32: u32 = 5000;

#[cfg(doc)]
use crate::{
    BZ_CONFIG_ERROR, BZ_DATA_ERROR, BZ_DATA_ERROR_MAGIC, BZ_FINISH, BZ_FINISH_OK, BZ_FLUSH,
    BZ_FLUSH_OK, BZ_IO_ERROR, BZ_MEM_ERROR, BZ_OK, BZ_OUTBUFF_FULL, BZ_PARAM_ERROR, BZ_RUN,
    BZ_RUN_OK, BZ_SEQUENCE_ERROR, BZ_STREAM_END, BZ_UNEXPECTED_EOF,
};

#[cfg(feature = "custom-prefix")]
macro_rules! prefix {
    ($name:expr) => {
        concat!(env!("LIBBZIP2_RS_SYS_PREFIX"), stringify!($name))
    };
}

#[cfg(all(
    not(feature = "custom-prefix"),
    not(any(test, feature = "testing-prefix"))
))]
macro_rules! prefix {
    ($name:expr) => {
        stringify!($name)
    };
}

#[cfg(all(not(feature = "custom-prefix"), any(test, feature = "testing-prefix")))]
macro_rules! prefix {
    ($name:expr) => {
        concat!("LIBBZIP2_RS_SYS_TEST_", stringify!($name))
    };
}

const LIBBZIP2_RS_SYS_VERSION: &str = concat!(libbzip2_rs_sys_version!(), "\0");

/// The version of the zlib library.
///
/// Its value is a pointer to a NULL-terminated sequence of bytes.
///
/// The version string for this release is `
#[doc = libbzip2_rs_sys_version!()]
/// `:
///
/// - The first component is the version of stock zlib that this release is compatible with
/// - The final component is the zlib-rs version used to build this release.
#[export_name = prefix!(BZ2_bzlibVersion)]
pub const extern "C" fn BZ2_bzlibVersion() -> *const core::ffi::c_char {
    LIBBZIP2_RS_SYS_VERSION.as_ptr().cast::<core::ffi::c_char>()
}

type AllocFunc = unsafe extern "C" fn(*mut c_void, c_int, c_int) -> *mut c_void;
type FreeFunc = unsafe extern "C" fn(*mut c_void, *mut c_void) -> ();

/// # Custom allocators
///
/// The low-level API supports passing in a custom allocator as part of the [`bz_stream`]:
///
/// ```no_check
/// struct bz_stream {
///     // ...
///     pub bzalloc: Option<unsafe extern "C" fn(_: *mut c_void, _: c_int, _: c_int) -> *mut c_void>,
///     pub bzfree: Option<unsafe extern "C" fn(_: *mut c_void, _: *mut c_void)>,
///     pub opaque: *mut c_void,
/// }
/// ```
/// The `strm.opaque` value is passed to as the first argument to all calls to `bzalloc`
/// and `bzfree`, but is otherwise ignored by the library.
///
/// When these fields are `NULL` and zero, the initialization functions will put in a default
/// allocator (currently based on `malloc` and `free`).
///
/// When custom functions are given, they must adhere to the following contract to be safe:
///
/// - a call `bzalloc(opaque, n, m)` must return a pointer `p` to `n * m` bytes of memory, or
///     `NULL` if out of memory
/// - a call `free(opaque, p)` must free that memory
#[allow(non_camel_case_types)]
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bz_stream {
    pub next_in: *const c_char,
    pub avail_in: c_uint,
    pub total_in_lo32: c_uint,
    pub total_in_hi32: c_uint,
    pub next_out: *mut c_char,
    pub avail_out: c_uint,
    pub total_out_lo32: c_uint,
    pub total_out_hi32: c_uint,
    pub state: *mut c_void,
    pub bzalloc: Option<AllocFunc>,
    pub bzfree: Option<FreeFunc>,
    pub opaque: *mut c_void,
}

impl bz_stream {
    pub const fn zeroed() -> Self {
        Self {
            next_in: ptr::null_mut::<c_char>(),
            avail_in: 0,
            total_in_lo32: 0,
            total_in_hi32: 0,
            next_out: ptr::null_mut::<c_char>(),
            avail_out: 0,
            total_out_lo32: 0,
            total_out_hi32: 0,
            state: ptr::null_mut::<c_void>(),
            bzalloc: None,
            bzfree: None,
            opaque: ptr::null_mut::<c_void>(),
        }
    }
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub(crate) enum ReturnCode {
    BZ_OK = 0,
    BZ_RUN_OK = 1,
    BZ_FLUSH_OK = 2,
    BZ_FINISH_OK = 3,
    BZ_STREAM_END = 4,
    BZ_SEQUENCE_ERROR = -1,
    BZ_PARAM_ERROR = -2,
    BZ_MEM_ERROR = -3,
    BZ_DATA_ERROR = -4,
    BZ_DATA_ERROR_MAGIC = -5,
    BZ_IO_ERROR = -6,
    BZ_UNEXPECTED_EOF = -7,
    BZ_OUTBUFF_FULL = -8,
    BZ_CONFIG_ERROR = -9,
}

#[derive(Copy, Clone)]
pub(crate) enum Mode {
    Idle = 1,
    Running = 2,
    Flushing = 3,
    Finishing = 4,
}

#[derive(Copy, Clone)]
pub(crate) enum State {
    Output = 1,
    Input = 2,
}

pub(crate) const BZ_N_RADIX: i32 = 2;
pub(crate) const BZ_N_QSORT: i32 = 12;
pub(crate) const BZ_N_SHELL: i32 = 18;
pub(crate) const BZ_N_OVERSHOOT: usize = (BZ_N_RADIX + BZ_N_QSORT + BZ_N_SHELL + 2) as usize;

pub(crate) const FTAB_LEN: usize = u16::MAX as usize + 2;

pub(crate) struct EState {
    pub strm_addr: usize, // Only for a consistency check
    pub mode: Mode,
    pub state: State,
    pub avail_in_expect: u32,
    pub arr1: Arr1,
    pub arr2: Arr2,
    pub ftab: Ftab,
    pub origPtr: i32,
    pub writer: crate::compress::EWriter,
    pub workFactor: i32,
    pub state_in_ch: u32,
    pub state_in_len: i32,
    pub nblock: i32,
    pub nblockMAX: i32,
    pub state_out_pos: i32,
    pub nInUse: i32,
    pub inUse: [bool; 256],
    pub unseqToSeq: [u8; 256],
    pub blockCRC: u32,
    pub combinedCRC: u32,
    pub verbosity: i32,
    pub blockNo: i32,
    pub blockSize100k: i32,
    pub nMTF: i32,
    pub mtfFreq: [i32; 258],
    pub selector: [u8; 18002],
    pub selectorMtf: [u8; 18002],
    pub len: [[u8; BZ_MAX_ALPHA_SIZE]; BZ_N_GROUPS],
    pub code: [[i32; 258]; 6],
    pub rfreq: [[i32; 258]; 6],
    pub len_pack: [[u32; 4]; 258],
}

/// Creates a new pointer that is dangling, but well-aligned.
pub(crate) fn dangling<T>() -> *mut T {
    ptr::null_mut::<T>().wrapping_add(mem::align_of::<T>())
}

pub(crate) struct Arr1 {
    ptr: *mut u32,
    len: usize,
}

impl Arr1 {
    unsafe fn alloc(bzalloc: AllocFunc, opaque: *mut c_void, len: usize) -> Option<Self> {
        let ptr = bzalloc_array(bzalloc, opaque, len)?;
        Some(Self { ptr, len })
    }

    unsafe fn dealloc(&mut self, bzfree: FreeFunc, opaque: *mut c_void) {
        let this = mem::replace(
            self,
            Self {
                ptr: dangling(),
                len: 0,
            },
        );
        if this.len != 0 {
            bzfree(opaque, this.ptr.cast())
        }
    }

    pub(crate) fn mtfv(&mut self) -> &mut [u16] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr.cast(), self.len * 2) }
    }

    pub(crate) fn ptr(&mut self) -> &mut [u32] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

pub(crate) struct Arr2 {
    ptr: *mut u32,
    len: usize,
}

impl Arr2 {
    unsafe fn alloc(bzalloc: AllocFunc, opaque: *mut c_void, len: usize) -> Option<Self> {
        let ptr = bzalloc_array(bzalloc, opaque, len)?;
        Some(Self { ptr, len })
    }

    unsafe fn dealloc(&mut self, bzfree: FreeFunc, opaque: *mut c_void) {
        let this = mem::replace(
            self,
            Self {
                ptr: dangling(),
                len: 0,
            },
        );
        if this.len != 0 {
            bzfree(opaque, this.ptr.cast())
        }
    }

    pub(crate) fn eclass(&mut self) -> &mut [u32] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    pub(crate) fn zbits(&mut self, nblock: usize) -> &mut [u8] {
        assert!(nblock <= 4 * self.len);
        unsafe {
            core::slice::from_raw_parts_mut(
                self.ptr.cast::<u8>().add(nblock),
                self.len * 4 - nblock,
            )
        }
    }

    pub(crate) fn raw_block(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr.cast(), self.len * 4) }
    }

    pub(crate) fn block(&mut self, nblock: usize) -> &mut [u8] {
        assert!(nblock <= 4 * self.len);
        unsafe { core::slice::from_raw_parts_mut(self.ptr.cast(), nblock) }
    }

    pub(crate) fn block_and_quadrant(&mut self, nblock: usize) -> (&mut [u8], &mut [u16]) {
        let len = nblock + BZ_N_OVERSHOOT;
        assert!(3 * len.next_multiple_of(2) <= 4 * self.len);

        let block = unsafe { core::slice::from_raw_parts_mut(self.ptr.cast(), len) };

        let start_byte = len.next_multiple_of(2);
        let quadrant: *mut u16 = (self.ptr as *mut u8).wrapping_add(start_byte) as *mut u16;
        unsafe { ptr::write_bytes(quadrant, 0, len) };
        let quadrant = unsafe { core::slice::from_raw_parts_mut(quadrant, len) };

        (block, quadrant)
    }
}

pub(crate) struct Ftab {
    ptr: *mut u32,
}

impl Ftab {
    unsafe fn alloc(bzalloc: AllocFunc, opaque: *mut c_void) -> Option<Self> {
        let ptr = bzalloc_array(bzalloc, opaque, FTAB_LEN)?;
        Some(Self { ptr })
    }

    unsafe fn dealloc(&mut self, bzfree: FreeFunc, opaque: *mut c_void) {
        let this = mem::replace(
            self,
            Self {
                ptr: ptr::null_mut(),
            },
        );
        if !this.ptr.is_null() {
            bzfree(opaque, this.ptr.cast())
        }
    }

    pub(crate) fn ftab(&mut self) -> &mut [u32; FTAB_LEN] {
        // NOTE: this panics if the pointer is NULL, that is important!
        unsafe { self.ptr.cast::<[u32; FTAB_LEN]>().as_mut().unwrap() }
    }
}

pub(crate) struct DState {
    pub strm_addr: usize, // Only for a consistency check
    pub state: decompress::State,
    pub state_out_ch: u8,
    pub state_out_len: i32,
    pub blockRandomised: bool,
    pub rNToGo: i32,
    pub rTPos: i32,
    pub bsBuff: u32,
    pub bsLive: i32,
    pub blockSize100k: i32,
    pub smallDecompress: DecompressMode,
    pub currBlockNo: i32,
    pub verbosity: i32,
    pub origPtr: i32,
    pub tPos: u32,
    pub k0: i32,
    pub unzftab: [i32; 256],
    pub nblock_used: i32,
    pub cftab: [i32; 257],
    pub cftabCopy: [i32; 257],
    pub tt: DSlice<u32>,
    pub ll16: DSlice<u16>,
    pub ll4: DSlice<u8>,
    pub storedBlockCRC: u32,
    pub storedCombinedCRC: u32,
    pub calculatedBlockCRC: u32,
    pub calculatedCombinedCRC: u32,
    pub nInUse: i32,
    pub inUse: [bool; 256],
    pub inUse16: [bool; 16],
    pub seqToUnseq: [u8; 256],
    pub mtfa: [u8; 4096],
    pub mtfbase: [i32; 16],
    pub selector: [u8; 18002],
    pub selectorMtf: [u8; 18002],
    pub len: [[u8; 258]; 6],
    pub limit: [[i32; 258]; 6],
    pub base: [[i32; 258]; 6],
    pub perm: [[i32; 258]; 6],
    pub minLens: [i32; 6],
    pub save_i: i32,
    pub save_j: i32,
    pub save_t: i32,
    pub save_alphaSize: i32,
    pub save_nGroups: i32,
    pub save_nSelectors: i32,
    pub save_EOB: i32,
    pub save_groupNo: i32,
    pub save_groupPos: i32,
    pub save_nextSym: i32,
    pub save_nblockMAX: i32,
    pub save_nblock: i32,
    pub save_es: i32,
    pub save_N: i32,
    pub save_curr: i32,
    pub save_zt: i32,
    pub save_zn: i32,
    pub save_zvec: i32,
    pub save_zj: i32,
    pub save_gSel: i32,
    pub save_gMinlen: i32,
    pub save_gLimit: i32,
    pub save_gBase: i32,
    pub save_gPerm: i32,
}

pub(crate) struct DSlice<T> {
    ptr: *mut T,
    len: usize,
}

impl<T> DSlice<T> {
    fn new() -> Self {
        Self {
            ptr: dangling(),
            len: 0,
        }
    }

    pub(crate) unsafe fn alloc(
        bzalloc: AllocFunc,
        opaque: *mut c_void,
        len: usize,
    ) -> Option<Self> {
        let ptr = bzalloc_array::<T>(bzalloc, opaque, len)?;
        Some(Self { ptr, len })
    }

    pub(crate) unsafe fn dealloc(&mut self, bzfree: FreeFunc, opaque: *mut c_void) {
        let this = mem::replace(self, Self::new());
        if this.len != 0 {
            bzfree(opaque, this.ptr.cast())
        }
    }

    pub(crate) fn as_slice(&self) -> &[T] {
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [T] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

/// Abstract handle to a `.bz2` file.
///
/// This type is created by:
///
/// - [`BZ2_bzReadOpen`]
/// - [`BZ2_bzWriteOpen`]
/// - [`BZ2_bzopen`]
///
/// And destructed by:
///
/// - [`BZ2_bzReadClose`]
/// - [`BZ2_bzWriteClose`]
/// - [`BZ2_bzclose`]
#[allow(non_camel_case_types)]
pub struct BZFILE {
    handle: *mut FILE,
    buf: [i8; BZ_MAX_UNUSED as usize],
    bufN: i32,
    strm: bz_stream,
    lastErr: ReturnCode,
    operation: Operation,
    initialisedOk: bool,
}

const _C_INT_SIZE: () = assert!(core::mem::size_of::<core::ffi::c_int>() == 4);
const _C_SHORT_SIZE: () = assert!(core::mem::size_of::<core::ffi::c_short>() == 2);
const _C_CHAR_SIZE: () = assert!(core::mem::size_of::<core::ffi::c_char>() == 1);

unsafe extern "C" fn default_bzalloc(_opaque: *mut c_void, items: i32, size: i32) -> *mut c_void {
    malloc((items * size) as usize)
}
unsafe extern "C" fn default_bzfree(_opaque: *mut c_void, addr: *mut c_void) {
    if !addr.is_null() {
        free(addr);
    }
}

fn prepare_new_block(s: &mut EState) {
    s.nblock = 0;
    s.writer.num_z = 0;
    s.state_out_pos = 0;
    s.blockCRC = 0xffffffff;
    s.inUse.fill(false);
    s.blockNo += 1;
}

fn init_rl(s: &mut EState) {
    s.state_in_ch = 256 as c_int as u32;
    s.state_in_len = 0 as c_int;
}

fn isempty_rl(s: &mut EState) -> bool {
    !(s.state_in_ch < 256 && s.state_in_len > 0)
}

/// Allocates `len` contiguous values of type `T`, and zeros out all elements.
///
/// # Safety
///
/// - `bzalloc` and `opaque` must form a valid allocator, meaning `bzalloc` returns either
///     * a `NULL` pointer
///     * a valid pointer to an allocation of `len * size_of::<T>()` bytes aligned to at least `align_of::<usize>()`
/// - the type `T` must be zeroable (i.e. an all-zero bit pattern is valid for `T`)
unsafe fn bzalloc_array<T>(bzalloc: AllocFunc, opaque: *mut c_void, len: usize) -> Option<*mut T> {
    assert!(core::mem::align_of::<T>() <= 16);

    let len = i32::try_from(len).ok()?;
    let width = i32::try_from(mem::size_of::<T>()).ok()?;

    let ptr = bzalloc(opaque, len, width).cast::<T>();

    if ptr.is_null() {
        return None;
    }

    ptr::write_bytes(ptr, 0, len as usize);

    Some(ptr)
}

/// Prepares the stream for compression.
///
/// # Returns
///
/// - [`BZ_PARAM_ERROR`] if any of
///     - `strm.is_null()`
///     - `!(1..=9).contains(&blockSize100k)`
///     - `!(0..=4).contains(&verbosity)`
///     - `!(0..=250).contains(&workFactor)`
/// - [`BZ_MEM_ERROR`] if insufficient memory is available
/// - [`BZ_OK`] otherwise
///
/// # Safety
///
/// The caller must guarantee that
///
/// * Either
///     - `strm` is `NULL`
///     - `strm` satisfies the requirements of `&mut *strm`
/// * The `bzalloc`, `bzfree` and `opaque` fields form a [valid allocator](bz_stream#custom-allocators).
#[export_name = prefix!(BZ2_bzCompressInit)]
pub unsafe extern "C" fn BZ2_bzCompressInit(
    strm: *mut bz_stream,
    blockSize100k: c_int,
    verbosity: c_int,
    workFactor: c_int,
) -> c_int {
    BZ2_bzCompressInitHelp(strm, blockSize100k, verbosity, workFactor) as c_int
}

unsafe fn BZ2_bzCompressInitHelp(
    strm: *mut bz_stream,
    blockSize100k: c_int,
    verbosity: c_int,
    mut workFactor: c_int,
) -> ReturnCode {
    if strm.is_null() || !(1..=9).contains(&blockSize100k) || !(0..=250).contains(&workFactor) {
        return ReturnCode::BZ_PARAM_ERROR;
    }

    if workFactor == 0 {
        workFactor = 30;
    }

    let bzalloc = *(*strm).bzalloc.get_or_insert(default_bzalloc);
    let bzfree = *(*strm).bzfree.get_or_insert(default_bzfree);

    let Some(s) = bzalloc_array::<EState>(bzalloc, (*strm).opaque, 1) else {
        return ReturnCode::BZ_MEM_ERROR;
    };

    // this `s.strm` pointer should _NEVER_ be used! it exists just as a consistency check to ensure
    // that a given state belongs to a given strm.
    (*s).strm_addr = strm as usize; // FIXME use .addr() once stable

    let n = 100000 * blockSize100k;

    let arr1_len = n as usize;
    let arr1 = Arr1::alloc(bzalloc, (*strm).opaque, arr1_len);

    let arr2_len = n as usize + (2 + 12 + 18 + 2);
    let arr2 = Arr2::alloc(bzalloc, (*strm).opaque, arr2_len);

    let ftab = Ftab::alloc(bzalloc, (*strm).opaque);

    match (arr1, arr2, ftab) {
        (Some(arr1), Some(arr2), Some(ftab)) => {
            (*s).arr1 = arr1;
            (*s).arr2 = arr2;
            (*s).ftab = ftab;
        }
        (arr1, arr2, ftab) => {
            if let Some(mut arr1) = arr1 {
                arr1.dealloc(bzfree, (*strm).opaque);
            }

            if let Some(mut arr2) = arr2 {
                arr2.dealloc(bzfree, (*strm).opaque);
            }

            if let Some(mut ftab) = ftab {
                ftab.dealloc(bzfree, (*strm).opaque);
            }

            (bzfree)((*strm).opaque, s as *mut c_void);

            return ReturnCode::BZ_MEM_ERROR;
        }
    };

    (*s).blockNo = 0;
    (*s).state = State::Output;
    (*s).mode = Mode::Running;
    (*s).combinedCRC = 0;
    (*s).blockSize100k = blockSize100k;
    (*s).nblockMAX = 100000 * blockSize100k - 19;
    (*s).verbosity = verbosity;
    (*s).workFactor = workFactor;

    (*strm).state = s as *mut c_void;

    (*strm).total_in_lo32 = 0;
    (*strm).total_in_hi32 = 0;
    (*strm).total_out_lo32 = 0;
    (*strm).total_out_hi32 = 0;

    init_rl(&mut *s);
    prepare_new_block(&mut *s);

    ReturnCode::BZ_OK
}

macro_rules! BZ_UPDATE_CRC {
    ($crcVar:expr, $cha:expr) => {
        let index = ($crcVar >> 24) ^ ($cha as core::ffi::c_uint);
        $crcVar = ($crcVar << 8) ^ BZ2_CRC32TABLE[index as usize];
    };
}

fn add_pair_to_block(s: &mut EState) {
    let ch: u8 = s.state_in_ch as u8;

    for _ in 0..s.state_in_len {
        BZ_UPDATE_CRC!(s.blockCRC, ch);
    }

    let block = s.arr2.raw_block();
    s.inUse[s.state_in_ch as usize] = true;
    match s.state_in_len {
        1 => {
            block[s.nblock as usize..][..1].fill(ch);
            s.nblock += 1;
        }
        2 => {
            block[s.nblock as usize..][..2].fill(ch);
            s.nblock += 2;
        }
        3 => {
            block[s.nblock as usize..][..3].fill(ch);
            s.nblock += 3;
        }
        _ => {
            s.inUse[(s.state_in_len - 4) as usize] = true;

            block[s.nblock as usize..][..4].fill(ch);
            s.nblock += 4;

            block[s.nblock as usize] = (s.state_in_len - 4) as u8;
            s.nblock += 1;
        }
    };
}

fn flush_rl(s: &mut EState) {
    if s.state_in_ch < 256 {
        add_pair_to_block(s);
    }
    init_rl(s);
}

macro_rules! ADD_CHAR_TO_BLOCK {
    ($zs:expr, $zchh0:expr) => {
        let zchh: u32 = $zchh0 as u32;

        if zchh != $zs.state_in_ch && $zs.state_in_len == 1 {
            /*-- fast track the common case --*/

            let ch: u8 = $zs.state_in_ch as u8;
            BZ_UPDATE_CRC!($zs.blockCRC, ch);
            $zs.inUse[$zs.state_in_ch as usize] = true;
            $zs.arr2.raw_block()[$zs.nblock as usize] = ch;
            $zs.nblock += 1;
            $zs.nblock;
            $zs.state_in_ch = zchh;
        } else if zchh != $zs.state_in_ch || $zs.state_in_len == 255 {
            /*-- general, uncommon cases --*/

            if $zs.state_in_ch < 256 {
                add_pair_to_block($zs);
            }
            $zs.state_in_ch = zchh;
            $zs.state_in_len = 1;
        } else {
            $zs.state_in_len += 1;
        }
    };
}

unsafe fn copy_input_until_stop(strm: &mut bz_stream, s: &mut EState) -> bool {
    let mut progress_in = false;

    match s.mode {
        Mode::Running => loop {
            if s.nblock >= s.nblockMAX {
                break;
            }
            if strm.avail_in == 0 {
                break;
            }
            progress_in = true;
            ADD_CHAR_TO_BLOCK!(s, *(strm.next_in as *mut u8) as u32);
            strm.next_in = (strm.next_in).offset(1);
            strm.avail_in = (strm.avail_in).wrapping_sub(1);
            strm.total_in_lo32 = (strm.total_in_lo32).wrapping_add(1);
            if strm.total_in_lo32 == 0 {
                strm.total_in_hi32 = (strm.total_in_hi32).wrapping_add(1);
            }
        },
        Mode::Idle | Mode::Flushing | Mode::Finishing => loop {
            if s.nblock >= s.nblockMAX {
                break;
            }
            if strm.avail_in == 0 {
                break;
            }
            if s.avail_in_expect == 0 {
                break;
            }
            progress_in = true;
            ADD_CHAR_TO_BLOCK!(s, *(strm.next_in as *mut u8) as u32);
            strm.next_in = (strm.next_in).offset(1);
            strm.avail_in = (strm.avail_in).wrapping_sub(1);
            strm.total_in_lo32 = (strm.total_in_lo32).wrapping_add(1);
            if strm.total_in_lo32 == 0 {
                strm.total_in_hi32 = (strm.total_in_hi32).wrapping_add(1);
            }
            s.avail_in_expect = (s.avail_in_expect).wrapping_sub(1);
        },
    }
    progress_in
}

unsafe fn copy_output_until_stop(strm: &mut bz_stream, s: &mut EState) -> bool {
    let mut progress_out = false;

    let zbits = &mut s.arr2.raw_block()[s.nblock as usize..];

    loop {
        if strm.avail_out == 0 {
            break;
        }
        if s.state_out_pos >= s.writer.num_z as i32 {
            break;
        }
        progress_out = true;
        *strm.next_out = zbits[s.state_out_pos as usize] as c_char;
        s.state_out_pos += 1;
        strm.avail_out = (strm.avail_out).wrapping_sub(1);
        strm.next_out = (strm.next_out).offset(1);
        strm.total_out_lo32 = (strm.total_out_lo32).wrapping_add(1);
        if strm.total_out_lo32 == 0 {
            strm.total_out_hi32 = (strm.total_out_hi32).wrapping_add(1);
        }
    }
    progress_out
}

unsafe fn handle_compress(strm: &mut bz_stream, s: &mut EState) -> bool {
    let mut progress_in = false;
    let mut progress_out = false;

    loop {
        if let State::Input = s.state {
            progress_out |= copy_output_until_stop(strm, s);
            if s.state_out_pos < s.writer.num_z as i32 {
                break;
            }
            if matches!(s.mode, Mode::Finishing) && s.avail_in_expect == 0 && isempty_rl(&mut *s) {
                break;
            }
            prepare_new_block(&mut *s);
            s.state = State::Output;
            if matches!(s.mode, Mode::Flushing) && s.avail_in_expect == 0 && isempty_rl(&mut *s) {
                break;
            }
        }
        if let State::Input = s.state {
            continue;
        }
        progress_in |= copy_input_until_stop(strm, s);
        if !matches!(s.mode, Mode::Running) && s.avail_in_expect == 0 {
            flush_rl(s);
            let is_last_block = matches!(s.mode, Mode::Finishing);
            compress_block(s, is_last_block);
            s.state = State::Input;
        } else if s.nblock >= s.nblockMAX {
            compress_block(s, false);
            s.state = State::Input;
        } else if strm.avail_in == 0 {
            break;
        }
    }

    progress_in || progress_out
}

pub(crate) enum Action {
    Run = 0,
    Flush = 1,
    Finish = 2,
}

impl TryFrom<i32> for Action {
    type Error = ();

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Run),
            1 => Ok(Self::Flush),
            2 => Ok(Self::Finish),
            _ => Err(()),
        }
    }
}

/// Compresses as much data as possible, and stops when the input buffer becomes empty or the output buffer becomes full.
///
/// # Returns
///
/// - [`BZ_SEQUENCE_ERROR`] if called on an invalid stream, e.g.
///     - before [`BZ2_bzCompressInit`]
///     - after [`BZ2_bzCompressEnd`]
/// - [`BZ_PARAM_ERROR`] if any of
///     - `strm.is_null()`
///     - `strm.s.is_null()`
///     - action is not one of [`BZ_RUN`], [`BZ_FLUSH`] or [`BZ_FINISH`]
/// - [`BZ_RUN_OK`] successfully compressed, but ran out of input or output space
/// - [`BZ_FLUSH_OK`] not all compressed data has been written to the output yet
/// - [`BZ_FINISH_OK`] if all input has been read but not all output has been written to the output
///     buffer yet
/// - [`BZ_STREAM_END`] if all input has been read all output has been written to the output buffer
///
/// # Safety
///
/// * Either
///     - `strm` is `NULL`
///     - `strm` satisfies the requirements of `&mut *strm` and was initialized with [`BZ2_bzCompressInit`]
/// * Either
///     - `strm.next_in` is `NULL` and `strm.avail_in` is 0
///     - `strm.next_in` is readable for `strm.avail_in` bytes
/// * Either
///     - `strm.next_out` is `NULL` and `strm.avail_out` is `0`
///     - `strm.next_out` is writable for `strm.avail_out` bytes
#[export_name = prefix!(BZ2_bzCompress)]
pub unsafe extern "C" fn BZ2_bzCompress(strm: *mut bz_stream, action: c_int) -> c_int {
    let Some(strm) = strm.as_mut() else {
        return ReturnCode::BZ_PARAM_ERROR as c_int;
    };

    BZ2_bzCompressHelp(strm, action) as c_int
}

unsafe fn BZ2_bzCompressHelp(strm: &mut bz_stream, action: i32) -> ReturnCode {
    let Some(s) = (strm.state as *mut EState).as_mut() else {
        return ReturnCode::BZ_PARAM_ERROR;
    };

    // FIXME use .addr() once stable
    if s.strm_addr != strm as *mut _ as usize {
        return ReturnCode::BZ_PARAM_ERROR;
    }

    compress_loop(strm, s, action)
}

unsafe fn compress_loop(strm: &mut bz_stream, s: &mut EState, action: i32) -> ReturnCode {
    loop {
        match s.mode {
            Mode::Idle => return ReturnCode::BZ_SEQUENCE_ERROR,
            Mode::Running => match Action::try_from(action) {
                Ok(Action::Run) => {
                    let progress = handle_compress(strm, s);
                    return if progress {
                        ReturnCode::BZ_RUN_OK
                    } else {
                        ReturnCode::BZ_PARAM_ERROR
                    };
                }
                Ok(Action::Flush) => {
                    s.avail_in_expect = strm.avail_in;
                    s.mode = Mode::Flushing;
                }
                Ok(Action::Finish) => {
                    s.avail_in_expect = strm.avail_in;
                    s.mode = Mode::Finishing;
                }
                Err(()) => {
                    return ReturnCode::BZ_PARAM_ERROR;
                }
            },
            Mode::Flushing => {
                let Ok(Action::Flush) = Action::try_from(action) else {
                    return ReturnCode::BZ_SEQUENCE_ERROR;
                };
                if s.avail_in_expect != strm.avail_in {
                    return ReturnCode::BZ_SEQUENCE_ERROR;
                }
                handle_compress(strm, s);
                if s.avail_in_expect > 0
                    || !isempty_rl(&mut *s)
                    || s.state_out_pos < s.writer.num_z as i32
                {
                    return ReturnCode::BZ_FLUSH_OK;
                }
                s.mode = Mode::Running;
                return ReturnCode::BZ_RUN_OK;
            }
            Mode::Finishing => {
                let Ok(Action::Finish) = Action::try_from(action) else {
                    // unreachable in practice
                    return ReturnCode::BZ_SEQUENCE_ERROR;
                };
                if s.avail_in_expect != strm.avail_in {
                    // unreachable in practice
                    return ReturnCode::BZ_SEQUENCE_ERROR;
                }
                let progress = handle_compress(strm, s);
                if !progress {
                    return ReturnCode::BZ_SEQUENCE_ERROR;
                }
                if s.avail_in_expect > 0
                    || !isempty_rl(s)
                    || s.state_out_pos < s.writer.num_z as i32
                {
                    return ReturnCode::BZ_FINISH_OK;
                }
                s.mode = Mode::Idle;
                return ReturnCode::BZ_STREAM_END;
            }
        }
    }
}

/// Deallocates all dynamically allocated data structures for this stream.
///
/// # Returns
///
/// - [`BZ_OK`] if success
/// - [`BZ_PARAM_ERROR`] if any of
///     - `strm.is_null()`
///     - `strm.s.is_null()`
///
/// # Safety
///
/// * Either
///     - `strm` is `NULL`
///     - `strm` satisfies the requirements of `&mut *strm` and was initialized with [`BZ2_bzCompressInit`]
#[export_name = prefix!(BZ2_bzCompressEnd)]
pub unsafe extern "C" fn BZ2_bzCompressEnd(strm: *mut bz_stream) -> c_int {
    let Some(strm) = strm.as_mut() else {
        return ReturnCode::BZ_PARAM_ERROR as c_int;
    };

    let Some(s) = (strm.state as *mut EState).as_mut() else {
        return ReturnCode::BZ_PARAM_ERROR as c_int;
    };

    // FIXME use .addr() once stable
    if s.strm_addr != strm as *mut _ as usize {
        return ReturnCode::BZ_PARAM_ERROR as c_int;
    }

    let Some(bzfree) = strm.bzfree else {
        return ReturnCode::BZ_PARAM_ERROR as c_int;
    };

    s.arr1.dealloc(bzfree, strm.opaque);
    s.arr2.dealloc(bzfree, strm.opaque);
    s.ftab.dealloc(bzfree, strm.opaque);

    (bzfree)(strm.opaque, strm.state);
    strm.state = ptr::null_mut::<c_void>();

    ReturnCode::BZ_OK as c_int
}

pub(crate) enum DecompressMode {
    Small,
    Fast,
}

/// Prepares the stream for decompression.
///
/// # Returns
///
/// - [`BZ_PARAM_ERROR`] if any of
///     - `strm.is_null()`
///     - `!(0..=1).contains(&small)`
///     - `!(0..=4).contains(&verbosity)`
/// - [`BZ_MEM_ERROR`] if insufficient memory is available
/// - [`BZ_OK`] otherwise
///
/// # Safety
///
/// The caller must guarantee that
///
/// * Either
///     - `strm` is `NULL`
///     - `strm` satisfies the requirements of `&mut *strm`
/// * The `bzalloc`, `bzfree` and `opaque` fields form a [valid allocator](bz_stream#custom-allocators).
#[export_name = prefix!(BZ2_bzDecompressInit)]
pub unsafe extern "C" fn BZ2_bzDecompressInit(
    strm: *mut bz_stream,
    verbosity: c_int,
    small: c_int,
) -> c_int {
    BZ2_bzDecompressInitHelp(strm, verbosity, small) as c_int
}

unsafe fn BZ2_bzDecompressInitHelp(
    strm: *mut bz_stream,
    verbosity: c_int,
    small: c_int,
) -> ReturnCode {
    if strm.is_null() {
        return ReturnCode::BZ_PARAM_ERROR;
    }
    let decompress_mode = match small {
        0 => DecompressMode::Fast,
        1 => DecompressMode::Small,
        _ => return ReturnCode::BZ_PARAM_ERROR,
    };
    if !(0..=4).contains(&verbosity) {
        return ReturnCode::BZ_PARAM_ERROR;
    }
    let bzalloc = (*strm).bzalloc.get_or_insert(default_bzalloc);
    let _bzfree = (*strm).bzfree.get_or_insert(default_bzfree);

    let Some(s) = bzalloc_array::<DState>(*bzalloc, (*strm).opaque, 1) else {
        return ReturnCode::BZ_MEM_ERROR;
    };

    // this `s.strm` pointer should _NEVER_ be used! it exists just as a consistency check to ensure
    // that a given state belongs to a given strm.
    (*s).strm_addr = strm as usize; // FIXME use .addr() once stable

    (*s).state = decompress::State::BZ_X_MAGIC_1;
    (*s).bsLive = 0;
    (*s).bsBuff = 0;
    (*s).calculatedCombinedCRC = 0;

    (*s).smallDecompress = decompress_mode;
    (*s).ll4 = DSlice::new();
    (*s).ll16 = DSlice::new();
    (*s).tt = DSlice::new();
    (*s).currBlockNo = 0;
    (*s).verbosity = verbosity;

    (*strm).state = s as *mut c_void;

    (*strm).total_in_lo32 = 0;
    (*strm).total_in_hi32 = 0;
    (*strm).total_out_lo32 = 0;
    (*strm).total_out_hi32 = 0;

    ReturnCode::BZ_OK
}

macro_rules! BZ_RAND_MASK {
    ($s:expr) => {
        ($s.rNToGo == 1) as u8
    };
}

macro_rules! BZ_RAND_UPD_MASK {
    ($s:expr) => {
        if ($s.rNToGo == 0) {
            $s.rNToGo = $crate::randtable::BZ2_RNUMS[$s.rTPos as usize];
            $s.rTPos += 1;
            if ($s.rTPos == 512) {
                $s.rTPos = 0
            };
        }
        $s.rNToGo -= 1;
    };
}

macro_rules! BZ_GET_FAST {
    ($s:expr, $cccc:expr) => {
        /* c_tPos is unsigned, hence test < 0 is pointless. */
        if $s.tPos >= 100000u32.wrapping_mul($s.blockSize100k as u32) {
            return true;
        }
        $s.tPos = $s.tt.as_slice()[$s.tPos as usize];
        $cccc = ($s.tPos & 0xff) as _;
        $s.tPos >>= 8;
    };
}

unsafe fn un_rle_obuf_to_output_fast(strm: &mut bz_stream, s: &mut DState) -> bool {
    let mut k1: u8;
    if s.blockRandomised {
        loop {
            /* try to finish existing run */
            loop {
                if strm.avail_out == 0 {
                    return false;
                }
                if s.state_out_len == 0 {
                    break;
                }
                *(strm.next_out as *mut u8) = s.state_out_ch;
                BZ_UPDATE_CRC!(s.calculatedBlockCRC, s.state_out_ch);
                s.state_out_len -= 1;
                strm.next_out = (strm.next_out).offset(1);
                strm.avail_out = (strm.avail_out).wrapping_sub(1);
                strm.total_out_lo32 = (strm.total_out_lo32).wrapping_add(1);
                if strm.total_out_lo32 == 0 {
                    strm.total_out_hi32 = (strm.total_out_hi32).wrapping_add(1);
                }
            }

            /* can a new run be started? */
            if s.nblock_used == s.save_nblock + 1 {
                return false;
            }

            /* Only caused by corrupt data stream? */
            if s.nblock_used > s.save_nblock + 1 {
                return true;
            }

            s.state_out_ch = s.k0 as u8;

            s.state_out_len = 1;
            BZ_GET_FAST!(s, k1);
            BZ_RAND_UPD_MASK!(s);
            k1 ^= BZ_RAND_MASK!(s);
            s.nblock_used += 1;
            if s.nblock_used == s.save_nblock + 1 {
                continue;
            };
            if k1 as i32 != s.k0 {
                s.k0 = k1 as i32;
                continue;
            };

            s.state_out_len = 2;
            BZ_GET_FAST!(s, k1);
            BZ_RAND_UPD_MASK!(s);
            k1 ^= BZ_RAND_MASK!(s);
            s.nblock_used += 1;
            if s.nblock_used == s.save_nblock + 1 {
                continue;
            };
            if k1 as i32 != s.k0 {
                s.k0 = k1 as i32;
                continue;
            };

            s.state_out_len = 3;
            BZ_GET_FAST!(s, k1);
            BZ_RAND_UPD_MASK!(s);
            k1 ^= BZ_RAND_MASK!(s);
            s.nblock_used += 1;
            if s.nblock_used == s.save_nblock + 1 {
                continue;
            };
            if k1 as i32 != s.k0 {
                s.k0 = k1 as i32;
                continue;
            };

            BZ_GET_FAST!(s, k1);
            BZ_RAND_UPD_MASK!(s);
            k1 ^= BZ_RAND_MASK!(s);
            s.nblock_used += 1;
            s.state_out_len = k1 as i32 + 4;
            BZ_GET_FAST!(s, s.k0);
            BZ_RAND_UPD_MASK!(s);
            s.k0 ^= BZ_RAND_MASK!(s) as i32;
            s.nblock_used += 1;
        }
    } else {
        enum NextState {
            OutLenEqOne,
            Remainder,
        }
        let mut current_block: NextState;

        /* restore */
        let mut c_calculatedBlockCRC: u32 = s.calculatedBlockCRC;
        let mut c_state_out_ch: u8 = s.state_out_ch;
        let mut c_state_out_len: i32 = s.state_out_len;
        let mut c_nblock_used: i32 = s.nblock_used;
        let mut c_k0: i32 = s.k0;
        let c_tt = 0usize;
        let mut c_tPos: u32 = s.tPos;
        let mut cs_next_out: *mut c_char = strm.next_out;
        let mut cs_avail_out: c_uint = strm.avail_out;
        let ro_blockSize100k: i32 = s.blockSize100k;
        /* end restore */

        let avail_out_INIT: u32 = cs_avail_out;
        let s_save_nblockPP: i32 = s.save_nblock + 1;

        macro_rules! BZ_GET_FAST_C {
            ( $cccc:expr) => {
                /* c_tPos is unsigned, hence test < 0 is pointless. */
                if c_tPos >= 100000u32.wrapping_mul(ro_blockSize100k as u32) {
                    return true;
                }
                c_tPos = s.tt.as_slice()[c_tt..][c_tPos as usize];
                $cccc = (c_tPos & 0xff) as _;
                c_tPos >>= 8;
            };
        }

        'return_notr: loop {
            if c_state_out_len > 0 {
                loop {
                    if cs_avail_out == 0 {
                        break 'return_notr;
                    }
                    if c_state_out_len == 1 {
                        break;
                    }
                    *(cs_next_out as *mut u8) = c_state_out_ch;
                    BZ_UPDATE_CRC!(c_calculatedBlockCRC, c_state_out_ch);
                    c_state_out_len -= 1;
                    cs_next_out = cs_next_out.offset(1);
                    cs_avail_out = cs_avail_out.wrapping_sub(1);
                }
                current_block = NextState::OutLenEqOne;
            } else {
                current_block = NextState::Remainder;
            }

            loop {
                match current_block {
                    NextState::OutLenEqOne => {
                        if cs_avail_out == 0 {
                            c_state_out_len = 1;
                            break 'return_notr;
                        } else {
                            *(cs_next_out as *mut u8) = c_state_out_ch;
                            BZ_UPDATE_CRC!(c_calculatedBlockCRC, c_state_out_ch);
                            cs_next_out = cs_next_out.offset(1);
                            cs_avail_out = cs_avail_out.wrapping_sub(1);
                            current_block = NextState::Remainder;
                        }
                    }
                    NextState::Remainder => {
                        /* Only caused by corrupt data stream? */
                        if c_nblock_used > s_save_nblockPP {
                            return true;
                        }

                        /* can a new run be started? */
                        if c_nblock_used == s_save_nblockPP {
                            c_state_out_len = 0;
                            break 'return_notr;
                        }

                        c_state_out_ch = c_k0 as u8;
                        BZ_GET_FAST_C!(k1);
                        c_nblock_used += 1;

                        if k1 as i32 != c_k0 {
                            c_k0 = k1 as i32;
                            current_block = NextState::OutLenEqOne;
                            continue;
                        }

                        if c_nblock_used == s_save_nblockPP {
                            current_block = NextState::OutLenEqOne;
                            continue;
                        }

                        c_state_out_len = 2;
                        BZ_GET_FAST_C!(k1);
                        c_nblock_used += 1;

                        if c_nblock_used == s_save_nblockPP {
                            continue 'return_notr;
                        }

                        if k1 as i32 != c_k0 {
                            c_k0 = k1 as i32;

                            continue 'return_notr;
                        }

                        c_state_out_len = 3;
                        BZ_GET_FAST_C!(k1);
                        c_nblock_used += 1;

                        if c_nblock_used == s_save_nblockPP {
                            continue 'return_notr;
                        }

                        if k1 as i32 != c_k0 {
                            c_k0 = k1 as i32;
                            continue 'return_notr;
                        }

                        BZ_GET_FAST_C!(k1);
                        c_nblock_used += 1;
                        c_state_out_len = k1 as i32 + 4;
                        BZ_GET_FAST_C!(c_k0);
                        c_nblock_used += 1;

                        break;
                    }
                }
            }
        }

        /* save */
        let total_out_lo32_old: c_uint = strm.total_out_lo32;
        strm.total_out_lo32 =
            (strm.total_out_lo32).wrapping_add(avail_out_INIT.wrapping_sub(cs_avail_out));
        if strm.total_out_lo32 < total_out_lo32_old {
            strm.total_out_hi32 = (strm.total_out_hi32).wrapping_add(1);
        }
        s.calculatedBlockCRC = c_calculatedBlockCRC;
        s.state_out_ch = c_state_out_ch;
        s.state_out_len = c_state_out_len;
        s.nblock_used = c_nblock_used;
        s.k0 = c_k0;
        // s.tt = c_tt; // as far as I can tell, this value is never actually updated
        s.tPos = c_tPos;
        strm.next_out = cs_next_out;
        strm.avail_out = cs_avail_out;
        /* end save */
    }

    false
}

#[inline]
pub(crate) fn index_into_f(indx: i32, cftab: &mut [i32]) -> i32 {
    let mut nb = 0;
    let mut na = 256;
    loop {
        let mid = (nb + na) >> 1;
        if indx >= cftab[mid as usize] {
            nb = mid;
        } else {
            na = mid;
        }
        if na - nb == 1 {
            break;
        }
    }
    nb
}

macro_rules! GET_LL4 {
    ($s:expr, $i:expr) => {
        $s.ll4.as_slice()[($s.tPos >> 1) as usize] as u32 >> ($s.tPos << 2 & 0x4) & 0xf
    };
}

macro_rules! GET_LL {
    ($s:expr, $i:expr) => {
        $s.ll16.as_slice()[$s.tPos as usize] as u32 | GET_LL4!($s, i) << 16
    };
}

macro_rules! BZ_GET_SMALL {
    ($s:expr, $cccc:expr) => {
        /* c_tPos is unsigned, hence test < 0 is pointless. */
        if $s.tPos >= 100000u32.wrapping_mul($s.blockSize100k as u32) {
            return true;
        }
        $cccc = index_into_f($s.tPos as i32, &mut $s.cftab) as _;
        $s.tPos = GET_LL!($s, $s.tPos);
    };
}

unsafe fn un_rle_obuf_to_output_small(strm: &mut bz_stream, s: &mut DState) -> bool {
    let mut k1: u8;
    if s.blockRandomised {
        loop {
            /* try to finish existing run */
            loop {
                if strm.avail_out == 0 {
                    return false;
                }
                if s.state_out_len == 0 {
                    break;
                }
                *(strm.next_out as *mut u8) = s.state_out_ch;
                BZ_UPDATE_CRC!(s.calculatedBlockCRC, s.state_out_ch);
                s.state_out_len -= 1;
                strm.next_out = (strm.next_out).offset(1);
                strm.avail_out = (strm.avail_out).wrapping_sub(1);
                strm.total_out_lo32 = (strm.total_out_lo32).wrapping_add(1);
                if strm.total_out_lo32 == 0 {
                    strm.total_out_hi32 = (strm.total_out_hi32).wrapping_add(1);
                }
            }

            /* can a new run be started? */
            if s.nblock_used == s.save_nblock + 1 {
                return false;
            }

            /* Only caused by corrupt data stream? */
            if s.nblock_used > s.save_nblock + 1 {
                return true;
            }

            s.state_out_ch = s.k0 as u8;

            s.state_out_len = 1;
            BZ_GET_SMALL!(s, k1);
            BZ_RAND_UPD_MASK!(s);
            k1 ^= BZ_RAND_MASK!(s);
            s.nblock_used += 1;
            if s.nblock_used == s.save_nblock + 1 {
                continue;
            };
            if k1 as i32 != s.k0 {
                s.k0 = k1 as i32;
                continue;
            };

            s.state_out_len = 2;
            BZ_GET_SMALL!(s, k1);
            BZ_RAND_UPD_MASK!(s);
            k1 ^= BZ_RAND_MASK!(s);
            s.nblock_used += 1;
            if s.nblock_used == s.save_nblock + 1 {
                continue;
            }
            if k1 as i32 != s.k0 {
                s.k0 = k1 as i32;
                continue;
            };

            s.state_out_len = 3;
            BZ_GET_SMALL!(s, k1);
            BZ_RAND_UPD_MASK!(s);
            k1 ^= BZ_RAND_MASK!(s);
            s.nblock_used += 1;
            if s.nblock_used == s.save_nblock + 1 {
                continue;
            }
            if k1 as i32 != s.k0 {
                s.k0 = k1 as i32;
                continue;
            };

            BZ_GET_SMALL!(s, k1);
            BZ_RAND_UPD_MASK!(s);
            k1 ^= BZ_RAND_MASK!(s);
            s.nblock_used += 1;
            s.state_out_len = k1 as i32 + 4;
            BZ_GET_SMALL!(s, s.k0);
            BZ_RAND_UPD_MASK!(s);
            s.k0 ^= BZ_RAND_MASK!(s) as i32;
            s.nblock_used += 1;
        }
    } else {
        loop {
            loop {
                if strm.avail_out == 0 {
                    return false;
                }
                if s.state_out_len == 0 {
                    break;
                }
                *(strm.next_out as *mut u8) = s.state_out_ch;
                BZ_UPDATE_CRC!(s.calculatedBlockCRC, s.state_out_ch);
                s.state_out_len -= 1;
                strm.next_out = (strm.next_out).offset(1);
                strm.avail_out = (strm.avail_out).wrapping_sub(1);
                strm.total_out_lo32 = (strm.total_out_lo32).wrapping_add(1);
                if strm.total_out_lo32 == 0 {
                    strm.total_out_hi32 = (strm.total_out_hi32).wrapping_add(1);
                }
            }
            if s.nblock_used == s.save_nblock + 1 {
                return false;
            }
            if s.nblock_used > s.save_nblock + 1 {
                return true;
            }

            s.state_out_len = 1;
            s.state_out_ch = s.k0 as u8;
            BZ_GET_SMALL!(s, k1);
            s.nblock_used += 1;
            if s.nblock_used == s.save_nblock + 1 {
                continue;
            }
            if k1 as i32 != s.k0 {
                s.k0 = k1 as i32;
                continue;
            };

            s.state_out_len = 2;
            BZ_GET_SMALL!(s, k1);
            s.nblock_used += 1;
            if s.nblock_used == s.save_nblock + 1 {
                continue;
            }
            if k1 as i32 != s.k0 {
                s.k0 = k1 as i32;
                continue;
            };

            s.state_out_len = 3;
            BZ_GET_SMALL!(s, k1);
            s.nblock_used += 1;
            if s.nblock_used == s.save_nblock + 1 {
                continue;
            }
            if k1 as i32 != s.k0 {
                s.k0 = k1 as i32;
                continue;
            };

            BZ_GET_SMALL!(s, k1);
            s.nblock_used += 1;
            s.state_out_len = k1 as i32 + 4;
            BZ_GET_SMALL!(s, s.k0);
            s.nblock_used += 1;
        }
    }
}

/// Decompresses as much data as possible, and stops when the input buffer becomes empty or the output buffer becomes full.
///
/// # Returns
///
/// - [`BZ_PARAM_ERROR`] if any of
///     - `strm.is_null()`
///     - `strm.s.is_null()`
///     - `strm.avail_out < 1`
/// - [`BZ_DATA_ERROR`] if a data integrity error is detected in the compressed stream
/// - [`BZ_DATA_ERROR_MAGIC`] if the compressed stream doesn't begin with the right magic bytes
/// - [`BZ_MEM_ERROR`] if there wasn't enough memory available
/// - [`BZ_STREAM_END`] if the logical end of the data stream was detected and all output has been
///     written to the output buffer
/// - [`BZ_OK`] otherwise
///
/// # Safety
///
/// * Either
///     - `strm` is `NULL`
///     - `strm` satisfies the requirements of `&mut *strm` and was initialized with [`BZ2_bzDecompressInit`]
/// * Either
///     - `strm.next_in` is `NULL` and `strm.avail_in` is 0
///     - `strm.next_in` is readable for `strm.avail_in` bytes
/// * Either
///     - `strm.next_out` is `NULL` and `strm.avail_out` is `0`
///     - `strm.next_out` is writable for `strm.avail_out` bytes
#[export_name = prefix!(BZ2_bzDecompress)]
pub unsafe extern "C" fn BZ2_bzDecompress(strm: *mut bz_stream) -> c_int {
    let Some(strm) = strm.as_mut() else {
        return ReturnCode::BZ_PARAM_ERROR as c_int;
    };

    BZ2_bzDecompressHelp(strm) as c_int
}

unsafe fn BZ2_bzDecompressHelp(strm: &mut bz_stream) -> ReturnCode {
    let Some(s) = (strm.state as *mut DState).as_mut() else {
        return ReturnCode::BZ_PARAM_ERROR;
    };

    // FIXME use .addr() once stable
    if s.strm_addr != strm as *mut _ as usize {
        return ReturnCode::BZ_PARAM_ERROR;
    }

    loop {
        if let decompress::State::BZ_X_IDLE = s.state {
            return ReturnCode::BZ_SEQUENCE_ERROR;
        }
        if let decompress::State::BZ_X_OUTPUT = s.state {
            let corrupt = match s.smallDecompress {
                DecompressMode::Small => un_rle_obuf_to_output_small(strm, s),
                DecompressMode::Fast => un_rle_obuf_to_output_fast(strm, s),
            };

            if corrupt {
                return ReturnCode::BZ_DATA_ERROR;
            }

            if s.nblock_used == s.save_nblock + 1 && s.state_out_len == 0 {
                s.calculatedBlockCRC = !s.calculatedBlockCRC;
                if s.verbosity >= 3 {
                    #[cfg(feature = "std")]
                    std::eprint!(
                        " {{{:#08x}, {:#08x}}}",
                        s.storedBlockCRC,
                        s.calculatedBlockCRC,
                    );
                }
                if s.verbosity >= 2 {
                    #[cfg(feature = "std")]
                    std::eprint!("]");
                }
                if s.calculatedBlockCRC != s.storedBlockCRC {
                    return ReturnCode::BZ_DATA_ERROR;
                }
                s.calculatedCombinedCRC = s.calculatedCombinedCRC.rotate_left(1);
                s.calculatedCombinedCRC ^= s.calculatedBlockCRC;
                s.state = decompress::State::BZ_X_BLKHDR_1;
            } else {
                return ReturnCode::BZ_OK;
            }
        }

        match s.state {
            decompress::State::BZ_X_IDLE | decompress::State::BZ_X_OUTPUT => continue,
            _ => match decompress(strm, s) {
                ReturnCode::BZ_STREAM_END => {
                    if s.verbosity >= 3 {
                        #[cfg(feature = "std")]
                        std::eprint!(
                            "\n    combined CRCs: stored = {:#08x}, computed = {:#08x}",
                            s.storedCombinedCRC,
                            s.calculatedCombinedCRC,
                        );
                    }
                    if s.calculatedCombinedCRC != s.storedCombinedCRC {
                        return ReturnCode::BZ_DATA_ERROR;
                    }
                    return ReturnCode::BZ_STREAM_END;
                }
                return_code => match s.state {
                    decompress::State::BZ_X_OUTPUT => continue,
                    _ => return return_code,
                },
            },
        }
    }
}

/// Deallocates all dynamically allocated data structures for this stream.
///
/// # Returns
///
/// - [`BZ_OK`] if success
/// - [`BZ_PARAM_ERROR`] if any of
///     - `strm.is_null()`
///     - `strm.s.is_null()`
///
/// # Safety
///
/// * Either
///     - `strm` is `NULL`
///     - `strm` satisfies the requirements of `&mut *strm` and was initialized with [`BZ2_bzDecompressInit`]
#[export_name = prefix!(BZ2_bzDecompressEnd)]
pub unsafe extern "C" fn BZ2_bzDecompressEnd(strm: *mut bz_stream) -> c_int {
    let Some(strm) = strm.as_mut() else {
        return ReturnCode::BZ_PARAM_ERROR as c_int;
    };

    let Some(s) = (strm.state as *mut DState).as_mut() else {
        return ReturnCode::BZ_PARAM_ERROR as c_int;
    };

    // FIXME use .addr() once stable
    if s.strm_addr != strm as *mut _ as usize {
        return ReturnCode::BZ_PARAM_ERROR as c_int;
    }

    let Some(bzfree) = strm.bzfree else {
        return ReturnCode::BZ_PARAM_ERROR as c_int;
    };

    s.tt.dealloc(bzfree, strm.opaque);
    s.ll16.dealloc(bzfree, strm.opaque);
    s.ll4.dealloc(bzfree, strm.opaque);

    (bzfree)(strm.opaque, strm.state.cast::<c_void>());
    strm.state = ptr::null_mut::<c_void>();

    ReturnCode::BZ_OK as c_int
}

unsafe fn myfeof(f: *mut FILE) -> bool {
    let c = fgetc(f);
    if c == -1 {
        return true;
    }

    ungetc(c, f);

    false
}

macro_rules! BZ_SETERR_RAW {
    ($bzerror:expr, $bzf:expr, $return_code:expr) => {
        if let Some(bzerror) = $bzerror.cast::<ReturnCode>().as_mut() {
            *bzerror = $return_code;
        }

        if let Some(bzf) = $bzf.as_mut() {
            bzf.lastErr = $return_code;
        }
    };
}

macro_rules! BZ_SETERR {
    ($bzerror:expr, $bzf:expr, $return_code:expr) => {
        if let Some(bzerror) = $bzerror.cast::<ReturnCode>().as_mut() {
            *bzerror = $return_code;
        }

        $bzf.lastErr = $return_code;
    };
}

/// Prepare to write compressed data to a file handle.
///
/// The file handle `f` should refer to a file which has been opened for writing, and for which the error indicator `libc::ferror(f)` is not set.
///
/// For the meaning of parameters `blockSize100k`, `verbosity` and `workFactor`, see [`BZ2_bzCompressInit`].
///
/// # Returns
///
/// - if `*bzerror` is [`BZ_OK`], a valid pointer to an abstract `BZFILE`
/// - otherwise `NULL`
///
/// # Possible assignments to `bzerror`
///
/// - [`BZ_PARAM_ERROR`] if any of
///     - `f.is_null`
///     - `!(1..=9).contains(&blockSize100k)`
///     - `!(0..=4).contains(&verbosity)`
///     - `!(0..=250).contains(&workFactor)`
/// - [`BZ_IO_ERROR`] if `libc::ferror(f)` is nonzero
/// - [`BZ_MEM_ERROR`] if insufficient memory is available
/// - [`BZ_OK`] otherwise
///
/// # Safety
///
/// The caller must guarantee that
///
/// * `bzerror` satisfies the requirements of [`pointer::as_mut`]
/// * Either
///     - `f` is `NULL`
///     - `f` a valid pointer to a `FILE`
///
/// [`pointer::as_mut`]: https://doc.rust-lang.org/core/primitive.pointer.html#method.as_mut
#[export_name = prefix!(BZ2_bzWriteOpen)]
pub unsafe extern "C" fn BZ2_bzWriteOpen(
    bzerror: *mut c_int,
    f: *mut FILE,
    blockSize100k: c_int,
    verbosity: c_int,
    mut workFactor: c_int,
) -> *mut BZFILE {
    let bzf = ptr::null_mut::<BZFILE>();

    BZ_SETERR_RAW!(bzerror, bzf, ReturnCode::BZ_OK);

    if f.is_null()
        || !(1..=9).contains(&blockSize100k)
        || !(0..=250).contains(&workFactor)
        || !(0..=4).contains(&verbosity)
    {
        BZ_SETERR_RAW!(bzerror, bzf, ReturnCode::BZ_PARAM_ERROR);
        return ptr::null_mut();
    }

    if ferror(f) != 0 {
        BZ_SETERR_RAW!(bzerror, bzf, ReturnCode::BZ_IO_ERROR);
        return ptr::null_mut();
    }

    let Some(bzf) = bzalloc_array::<BZFILE>(default_bzalloc, ptr::null_mut(), 1) else {
        BZ_SETERR_RAW!(bzerror, bzf, ReturnCode::BZ_MEM_ERROR);
        return ptr::null_mut();
    };

    // SAFETY: bzf is non-null and correctly initalized
    let bzf = unsafe { &mut *bzf };

    BZ_SETERR!(bzerror, bzf, ReturnCode::BZ_OK);

    bzf.initialisedOk = false;
    bzf.bufN = 0;
    bzf.handle = f;
    bzf.operation = Operation::Writing;
    bzf.strm.bzalloc = None;
    bzf.strm.bzfree = None;
    bzf.strm.opaque = ptr::null_mut();

    if workFactor == 0 {
        workFactor = 30;
    }

    match BZ2_bzCompressInitHelp(&mut bzf.strm, blockSize100k, verbosity, workFactor) {
        ReturnCode::BZ_OK => {
            bzf.strm.avail_in = 0;
            bzf.initialisedOk = true;

            bzf as *mut BZFILE
        }
        error => {
            BZ_SETERR!(bzerror, bzf, error);
            free(bzf as *mut BZFILE as *mut c_void);

            ptr::null_mut()
        }
    }
}

/// Absorbs `len` bytes from the buffer `buf`, eventually to be compressed and written to the file.
///
/// # Returns
///
/// # Possible assignments to `bzerror`
///
/// - [`BZ_PARAM_ERROR`] if any of
///     - `b.is_null()`
///     - `buf.is_null()`
///     - `len < 0`
/// - [`BZ_SEQUENCE_ERROR`] if b was opened with [`BZ2_bzReadOpen`]
/// - [`BZ_IO_ERROR`] if there is an error writing to the compressed file
/// - [`BZ_OK`] otherwise
///
/// # Safety
///
/// The caller must guarantee that
///
/// * `bzerror` satisfies the requirements of [`pointer::as_mut`]
/// * Either
///     - `b` is `NULL`
///     - `b` is initialized with [`BZ2_bzWriteOpen`] or [`BZ2_bzReadOpen`]
/// * Either
///     - `buf` is `NULL`
///     - `buf` is writable for `len` bytes
///
/// [`pointer::as_mut`]: https://doc.rust-lang.org/core/primitive.pointer.html#method.as_mut
#[export_name = prefix!(BZ2_bzWrite)]
pub unsafe extern "C" fn BZ2_bzWrite(
    bzerror: *mut c_int,
    b: *mut BZFILE,
    buf: *const c_void,
    len: c_int,
) {
    BZ_SETERR_RAW!(bzerror, b, ReturnCode::BZ_OK);

    let Some(bzf) = b.as_mut() else {
        BZ_SETERR_RAW!(bzerror, b, ReturnCode::BZ_PARAM_ERROR);
        return;
    };

    if buf.is_null() || len < 0 as c_int {
        BZ_SETERR!(bzerror, bzf, ReturnCode::BZ_PARAM_ERROR);
        return;
    }

    if !matches!(bzf.operation, Operation::Writing) {
        BZ_SETERR!(bzerror, bzf, ReturnCode::BZ_SEQUENCE_ERROR);
        return;
    }

    if ferror(bzf.handle) != 0 {
        BZ_SETERR!(bzerror, bzf, ReturnCode::BZ_IO_ERROR);
        return;
    }

    if len == 0 {
        BZ_SETERR!(bzerror, bzf, ReturnCode::BZ_OK);
        return;
    }

    bzf.strm.avail_in = len as c_uint;
    bzf.strm.next_in = buf.cast::<c_char>();

    loop {
        bzf.strm.avail_out = BZ_MAX_UNUSED_U32;
        bzf.strm.next_out = bzf.buf.as_mut_ptr().cast::<c_char>();
        match BZ2_bzCompressHelp(&mut bzf.strm, Action::Run as c_int) {
            ReturnCode::BZ_RUN_OK => {
                if bzf.strm.avail_out < BZ_MAX_UNUSED_U32 {
                    let n1 = BZ_MAX_UNUSED_U32.wrapping_sub(bzf.strm.avail_out) as usize;
                    let n2 = fwrite(
                        bzf.buf.as_mut_ptr().cast::<c_void>(),
                        mem::size_of::<u8>(),
                        n1,
                        bzf.handle,
                    );
                    if n1 != n2 || ferror(bzf.handle) != 0 {
                        BZ_SETERR!(bzerror, bzf, ReturnCode::BZ_IO_ERROR);
                        return;
                    }
                }
                if bzf.strm.avail_in == 0 {
                    BZ_SETERR!(bzerror, bzf, ReturnCode::BZ_OK);
                    return;
                }
            }
            error => {
                BZ_SETERR!(bzerror, bzf, error);
                return;
            }
        }
    }
}

/// Compresses and flushes to the compressed file all data so far supplied by [`BZ2_bzWrite`].
///
/// The logical end-of-stream markers are also written, so subsequent calls to [`BZ2_bzWrite`] are illegal.
/// All memory associated with the compressed file `b` is released. [`libc::fflush`] is called on the compressed file,
/// but it is not [`libc::fclose`]'d.
///
/// If [`BZ2_bzWriteClose`] is called to clean up after an error, the only action is to release the memory.
/// The library records the error codes issued by previous calls, so this situation will be detected automatically.
/// There is no attempt to complete the compression operation, nor to [`libc::fflush`] the compressed file.
/// You can force this behaviour to happen even in the case of no error, by passing a nonzero value to `abandon`.
///
/// # Possible assignments to `bzerror`
///
/// - [`BZ_SEQUENCE_ERROR`] if b was opened with [`BZ2_bzWriteOpen`]
/// - [`BZ_IO_ERROR`] if there is an error writing to the compressed file
/// - [`BZ_OK`] otherwise
///
/// # Safety
///
/// The caller must guarantee that
///
/// * `bzerror` satisfies the requirements of [`pointer::as_mut`]
/// * Either
///     - `b` is `NULL`
///     - `b` is initialized with [`BZ2_bzReadOpen`] or [`BZ2_bzWriteOpen`]
/// * `nbytes_in` satisfies the requirements of [`pointer::as_mut`]
/// * `nbytes_out` satisfies the requirements of [`pointer::as_mut`]
///
/// [`pointer::as_mut`]: https://doc.rust-lang.org/core/primitive.pointer.html#method.as_mut
#[export_name = prefix!(BZ2_bzWriteClose)]
pub unsafe extern "C" fn BZ2_bzWriteClose(
    bzerror: *mut c_int,
    b: *mut BZFILE,
    abandon: c_int,
    nbytes_in: *mut c_uint,
    nbytes_out: *mut c_uint,
) {
    BZ2_bzWriteClose64(
        bzerror,
        b,
        abandon,
        nbytes_in,
        ptr::null_mut::<c_uint>(),
        nbytes_out,
        ptr::null_mut::<c_uint>(),
    );
}

/// Compresses and flushes to the compressed file all data so far supplied by [`BZ2_bzWrite`].
///
/// The logical end-of-stream markers are also written, so subsequent calls to [`BZ2_bzWrite`] are illegal.
/// All memory associated with the compressed file `b` is released. [`libc::fflush`] is called on the compressed file,
/// but it is not [`libc::fclose`]'d.
///
/// If [`BZ2_bzWriteClose64`] is called to clean up after an error, the only action is to release the memory.
/// The library records the error codes issued by previous calls, so this situation will be detected automatically.
/// There is no attempt to complete the compression operation, nor to [`libc::fflush`] the compressed file.
/// You can force this behaviour to happen even in the case of no error, by passing a nonzero value to `abandon`.
///
/// # Possible assignments to `bzerror`
///
/// - [`BZ_SEQUENCE_ERROR`] if b was opened with [`BZ2_bzWriteOpen`]
/// - [`BZ_IO_ERROR`] if there is an error writing to the compressed file
/// - [`BZ_OK`] otherwise
///
/// # Safety
///
/// The caller must guarantee that
///
/// * `bzerror` satisfies the requirements of [`pointer::as_mut`]
/// * Either
///     - `b` is `NULL`
///     - `b` is initialized with [`BZ2_bzReadOpen`] or [`BZ2_bzWriteOpen`]
/// * `nbytes_in_lo32: satisfies the requirements of [`pointer::as_mut`]
/// * `nbytes_in_hi32: satisfies the requirements of [`pointer::as_mut`]
/// * `nbytes_out_lo32: satisfies the requirements of [`pointer::as_mut`]
/// * `nbytes_out_hi32: satisfies the requirements of [`pointer::as_mut`]
///
/// [`pointer::as_mut`]: https://doc.rust-lang.org/core/primitive.pointer.html#method.as_mut
#[export_name = prefix!(BZ2_bzWriteClose64)]
pub unsafe extern "C" fn BZ2_bzWriteClose64(
    bzerror: *mut c_int,
    b: *mut BZFILE,
    abandon: c_int,
    nbytes_in_lo32: *mut c_uint,
    nbytes_in_hi32: *mut c_uint,
    nbytes_out_lo32: *mut c_uint,
    nbytes_out_hi32: *mut c_uint,
) {
    let Some(bzf) = b.as_mut() else {
        BZ_SETERR_RAW!(bzerror, b, ReturnCode::BZ_PARAM_ERROR);
        return;
    };

    if !matches!(bzf.operation, Operation::Writing) {
        BZ_SETERR!(bzerror, bzf, ReturnCode::BZ_SEQUENCE_ERROR);
        return;
    }

    if ferror(bzf.handle) != 0 {
        BZ_SETERR!(bzerror, bzf, ReturnCode::BZ_IO_ERROR);
        return;
    }

    if let Some(nbytes_in_lo32) = nbytes_in_lo32.as_mut() {
        *nbytes_in_lo32 = 0
    }
    if let Some(nbytes_in_hi32) = nbytes_in_hi32.as_mut() {
        *nbytes_in_hi32 = 0;
    }
    if let Some(nbytes_out_lo32) = nbytes_out_lo32.as_mut() {
        *nbytes_out_lo32 = 0;
    }
    if let Some(nbytes_out_hi32) = nbytes_out_hi32.as_mut() {
        *nbytes_out_hi32 = 0;
    }

    if abandon == 0 && bzf.lastErr == ReturnCode::BZ_OK {
        loop {
            bzf.strm.avail_out = BZ_MAX_UNUSED_U32;
            bzf.strm.next_out = (bzf.buf).as_mut_ptr().cast::<c_char>();
            match BZ2_bzCompressHelp(&mut bzf.strm, 2 as c_int) {
                ret @ (ReturnCode::BZ_FINISH_OK | ReturnCode::BZ_STREAM_END) => {
                    if bzf.strm.avail_out < BZ_MAX_UNUSED_U32 {
                        let n1 = BZ_MAX_UNUSED_U32.wrapping_sub(bzf.strm.avail_out) as usize;
                        let n2 = fwrite(
                            bzf.buf.as_mut_ptr().cast::<c_void>(),
                            mem::size_of::<u8>(),
                            n1,
                            bzf.handle,
                        );
                        if n1 != n2 || ferror(bzf.handle) != 0 {
                            BZ_SETERR!(bzerror, bzf, ReturnCode::BZ_IO_ERROR);
                        }
                    }

                    if let ReturnCode::BZ_STREAM_END = ret {
                        break;
                    }
                }
                ret => {
                    BZ_SETERR!(bzerror, bzf, ret);
                    return;
                }
            }
        }
    }

    if abandon == 0 && ferror(bzf.handle) == 0 {
        fflush(bzf.handle);
        if ferror(bzf.handle) != 0 {
            BZ_SETERR!(bzerror, bzf, ReturnCode::BZ_IO_ERROR);
            return;
        }
    }

    if let Some(nbytes_in_lo32) = nbytes_in_lo32.as_mut() {
        *nbytes_in_lo32 = bzf.strm.total_in_lo32;
    }
    if let Some(nbytes_in_hi32) = nbytes_in_hi32.as_mut() {
        *nbytes_in_hi32 = bzf.strm.total_in_hi32;
    }
    if let Some(nbytes_out_lo32) = nbytes_out_lo32.as_mut() {
        *nbytes_out_lo32 = bzf.strm.total_out_lo32;
    }
    if let Some(nbytes_out_hi32) = nbytes_out_hi32.as_mut() {
        *nbytes_out_hi32 = bzf.strm.total_out_hi32;
    }

    BZ_SETERR!(bzerror, bzf, ReturnCode::BZ_OK);

    BZ2_bzCompressEnd(&mut bzf.strm);
    free(bzf as *mut BZFILE as *mut c_void);
}

/// Prepare to read compressed data from a file handle.
///
/// The file handle `f` should refer to a file which has been opened for reading, and for which the error indicator `libc::ferror(f)` is not set.
///
/// If small is 1, the library will try to decompress using less memory, at the expense of speed.
///
/// For reasons explained below, [`BZ2_bzRead`] will decompress the nUnused bytes starting at unused, before starting to read from the file `f`.
/// At most [`BZ_MAX_UNUSED`] bytes may be supplied like this. If this facility is not required, you should pass NULL and 0 for unused and nUnused respectively.
///
/// For the meaning of parameters `small`, `verbosity`, see [`BZ2_bzDecompressInit`].
///
/// Because the compression ratio of the compressed data cannot be known in advance,
/// there is no easy way to guarantee that the output buffer will be big enough.
/// You may of course make arrangements in your code to record the size of the uncompressed data,
/// but such a mechanism is beyond the scope of this library.
///
/// # Returns
///
/// - if `*bzerror` is [`BZ_OK`], a valid pointer to an abstract `BZFILE`
/// - otherwise `NULL`
///
/// # Possible assignments to `bzerror`
///
/// - [`BZ_PARAM_ERROR`] if any of
///     - `(unused.is_null() && nUnused != 0)`
///     - `(!unused.is_null() && !(0..=BZ_MAX_UNUSED).contains(&nUnused))`
///     - `!(0..=1).contains(&small)`
///     - `!(0..=4).contains(&verbosity)`
/// - [`BZ_IO_ERROR`] if `libc::ferror(f)` is nonzero
/// - [`BZ_MEM_ERROR`] if insufficient memory is available
/// - [`BZ_OK`] otherwise
///
/// # Safety
///
/// The caller must guarantee that
///
/// * `bzerror` satisfies the requirements of [`pointer::as_mut`]
/// * Either
///     - `unused` is `NULL`
///     - `unused` is readable for `nUnused` bytes
///
/// [`pointer::as_mut`]: https://doc.rust-lang.org/core/primitive.pointer.html#method.as_mut
#[export_name = prefix!(BZ2_bzReadOpen)]
pub unsafe extern "C" fn BZ2_bzReadOpen(
    bzerror: *mut c_int,
    f: *mut FILE,
    verbosity: c_int,
    small: c_int,
    unused: *mut c_void,
    nUnused: c_int,
) -> *mut BZFILE {
    let bzf: *mut BZFILE = ptr::null_mut::<BZFILE>();

    BZ_SETERR_RAW!(bzerror, bzf, ReturnCode::BZ_OK);

    if f.is_null()
        || !(0..=1).contains(&small)
        || !(0..=4).contains(&verbosity)
        || (unused.is_null() && nUnused != 0)
        || (!unused.is_null() && !(0..=BZ_MAX_UNUSED_U32 as c_int).contains(&nUnused))
    {
        BZ_SETERR_RAW!(bzerror, bzf, ReturnCode::BZ_PARAM_ERROR);
        return ptr::null_mut::<BZFILE>();
    }

    if ferror(f) != 0 {
        BZ_SETERR_RAW!(bzerror, bzf, ReturnCode::BZ_IO_ERROR);
        return ptr::null_mut::<BZFILE>();
    }

    let Some(bzf) = bzalloc_array::<BZFILE>(default_bzalloc, ptr::null_mut(), 1) else {
        BZ_SETERR_RAW!(bzerror, bzf, ReturnCode::BZ_MEM_ERROR);
        return ptr::null_mut();
    };

    // SAFETY: bzf is non-null and correctly initalized
    let bzf = unsafe { &mut *bzf };

    BZ_SETERR!(bzerror, bzf, ReturnCode::BZ_OK);

    bzf.initialisedOk = false;
    bzf.handle = f;
    bzf.bufN = 0;
    bzf.operation = Operation::Reading;
    bzf.strm.bzalloc = None;
    bzf.strm.bzfree = None;
    bzf.strm.opaque = ptr::null_mut();

    if nUnused > 0 {
        ptr::copy(
            unused as *mut i8,
            bzf.buf[bzf.bufN as usize..].as_mut_ptr(),
            nUnused as usize,
        );
        bzf.bufN += nUnused;
    }

    match BZ2_bzDecompressInitHelp(&mut bzf.strm, verbosity, small) {
        ReturnCode::BZ_OK => {
            bzf.strm.avail_in = bzf.bufN as c_uint;
            bzf.strm.next_in = bzf.buf.as_mut_ptr().cast::<c_char>();
            bzf.initialisedOk = true;
        }
        ret => {
            BZ_SETERR!(bzerror, bzf, ret);
            free(bzf as *mut BZFILE as *mut c_void);
            return ptr::null_mut();
        }
    }

    bzf as *mut BZFILE
}

/// Releases all memory associated with a [`BZFILE`] opened with [`BZ2_bzReadOpen`].
///
/// This function does not call `fclose` on the underlying file handle, the caller should close the
/// file if appropriate.
///
/// This function should be called to clean up after all error situations on `BZFILE`s opened with
/// [`BZ2_bzReadOpen`].
///
/// # Possible assignments to `bzerror`
///
/// - [`BZ_SEQUENCE_ERROR`] if b was opened with [`BZ2_bzWriteOpen`]
/// - [`BZ_OK`] otherwise
///
/// # Safety
///
/// The caller must guarantee that
///
/// * `bzerror` satisfies the requirements of [`pointer::as_mut`]
/// * Either
///     - `b` is `NULL`
///     - `b` is initialized with [`BZ2_bzReadOpen`] or [`BZ2_bzWriteOpen`]
///
/// [`pointer::as_mut`]: https://doc.rust-lang.org/core/primitive.pointer.html#method.as_mut
#[export_name = prefix!(BZ2_bzReadClose)]
pub unsafe extern "C" fn BZ2_bzReadClose(bzerror: *mut c_int, b: *mut BZFILE) {
    BZ_SETERR_RAW!(bzerror, b, ReturnCode::BZ_OK);

    let Some(bzf) = b.as_mut() else {
        BZ_SETERR_RAW!(bzerror, b, ReturnCode::BZ_OK);
        return;
    };

    if !matches!(bzf.operation, Operation::Reading) {
        BZ_SETERR!(bzerror, bzf, ReturnCode::BZ_SEQUENCE_ERROR);
        return;
    }

    if bzf.initialisedOk {
        BZ2_bzDecompressEnd(&mut bzf.strm);
    }

    free(bzf as *mut BZFILE as *mut c_void);
}

/// Reads up to `len` (uncompressed) bytes from the compressed file `b` into the buffer `buf`.
///
/// # Returns
///
/// The number of bytes read
///
/// # Possible assignments to `bzerror`
///
/// - [`BZ_PARAM_ERROR`] if any of
///     - `b.is_null()`
///     - `buf.is_null()`
///     - `len < 0`
/// - [`BZ_SEQUENCE_ERROR`] if b was opened with [`BZ2_bzWriteOpen`]
/// - [`BZ_IO_ERROR`] if there is an error reading from the compressed file
/// - [`BZ_UNEXPECTED_EOF`] if the compressed data ends before the logical end-of-stream was detected
/// - [`BZ_DATA_ERROR`] if a data integrity error is detected in the compressed stream
/// - [`BZ_DATA_ERROR_MAGIC`] if the compressed stream doesn't begin with the right magic bytes
/// - [`BZ_MEM_ERROR`] if insufficient memory is available
/// - [`BZ_STREAM_END`] if the logical end-of-stream was detected
/// - [`BZ_OK`] otherwise
///
/// # Safety
///
/// The caller must guarantee that
///
/// * `bzerror` satisfies the requirements of [`pointer::as_mut`]
/// * Either
///     - `b` is `NULL`
///     - `b` is initialized with [`BZ2_bzReadOpen`] or [`BZ2_bzWriteOpen`]
/// * Either
///     - `buf` is `NULL`
///     - `buf` is writable for `len` bytes
///
/// [`pointer::as_mut`]: https://doc.rust-lang.org/core/primitive.pointer.html#method.as_mut
#[export_name = prefix!(BZ2_bzRead)]
pub unsafe extern "C" fn BZ2_bzRead(
    bzerror: *mut c_int,
    b: *mut BZFILE,
    buf: *mut c_void,
    len: c_int,
) -> c_int {
    BZ_SETERR_RAW!(bzerror, b, ReturnCode::BZ_OK);

    let Some(bzf) = b.as_mut() else {
        BZ_SETERR_RAW!(bzerror, b, ReturnCode::BZ_PARAM_ERROR);
        return 0;
    };

    if buf.is_null() || len < 0 {
        BZ_SETERR!(bzerror, bzf, ReturnCode::BZ_PARAM_ERROR);
        return 0;
    }

    if !matches!(bzf.operation, Operation::Reading) {
        BZ_SETERR!(bzerror, bzf, ReturnCode::BZ_SEQUENCE_ERROR);
        return 0;
    }

    if len == 0 as c_int {
        BZ_SETERR!(bzerror, bzf, ReturnCode::BZ_OK);
        return 0;
    }

    bzf.strm.avail_out = len as c_uint;
    bzf.strm.next_out = buf as *mut c_char;
    loop {
        if ferror(bzf.handle) != 0 {
            BZ_SETERR!(bzerror, bzf, ReturnCode::BZ_IO_ERROR);
            return 0;
        }

        if bzf.strm.avail_in == 0 && !myfeof(bzf.handle) {
            let n = fread(
                (bzf.buf).as_mut_ptr() as *mut c_void,
                ::core::mem::size_of::<u8>(),
                5000,
                bzf.handle,
            ) as i32;

            if ferror(bzf.handle) != 0 {
                BZ_SETERR!(bzerror, bzf, ReturnCode::BZ_IO_ERROR);
                return 0;
            }

            bzf.bufN = n;
            bzf.strm.avail_in = bzf.bufN as c_uint;
            bzf.strm.next_in = (bzf.buf).as_mut_ptr().cast::<c_char>();
        }

        match BZ2_bzDecompressHelp(&mut bzf.strm) {
            ReturnCode::BZ_OK => {
                if myfeof(bzf.handle) && bzf.strm.avail_in == 0 && bzf.strm.avail_out > 0 {
                    BZ_SETERR!(bzerror, bzf, ReturnCode::BZ_UNEXPECTED_EOF);
                    return 0;
                } else if bzf.strm.avail_out == 0 {
                    BZ_SETERR!(bzerror, bzf, ReturnCode::BZ_OK);
                    return len;
                } else {
                    continue;
                }
            }
            ReturnCode::BZ_STREAM_END => {
                BZ_SETERR!(bzerror, bzf, ReturnCode::BZ_STREAM_END);
                return (len as c_uint).wrapping_sub(bzf.strm.avail_out) as c_int;
            }
            error => {
                BZ_SETERR!(bzerror, bzf, error);
                return 0;
            }
        }
    }
}

/// Returns data which was read from the compressed file but was not needed to get to the logical end-of-stream.
///
/// # Returns
///
/// - `*unused` is set to the address of the data
/// - `*nUnused` is set to the number of bytes.
///
/// `*nUnused` will be set to a value contained in `0..=BZ_MAX_UNUSED`.
///
/// # Possible assignments to `bzerror`
///
/// - [`BZ_PARAM_ERROR`] if any of
///     - `b.is_null()`
///     - `unused.is_null()`
///     - `nUnused.is_null()`
/// - [`BZ_SEQUENCE_ERROR`] if any of
///     - [`BZ_STREAM_END`] has not been signaled
///     - b was opened with [`BZ2_bzWriteOpen`]
/// - [`BZ_OK`] otherwise
///
/// # Safety
///
/// The caller must guarantee that
///
/// * `bzerror` satisfies the requirements of [`pointer::as_mut`]
/// * `unused` satisfies the requirements of [`pointer::as_mut`]
/// * `nUnused` satisfies the requirements of [`pointer::as_mut`]
/// * Either
///     - `b` is `NULL`
///     - `b` is initialized with [`BZ2_bzReadOpen`] or [`BZ2_bzWriteOpen`]
///
/// [`pointer::as_mut`]: https://doc.rust-lang.org/core/primitive.pointer.html#method.as_mut
#[export_name = prefix!(BZ2_bzReadGetUnused)]
pub unsafe extern "C" fn BZ2_bzReadGetUnused(
    bzerror: *mut c_int,
    b: *mut BZFILE,
    unused: *mut *mut c_void,
    nUnused: *mut c_int,
) {
    let Some(bzf) = b.as_mut() else {
        BZ_SETERR_RAW!(bzerror, b, ReturnCode::BZ_PARAM_ERROR);
        return;
    };

    if bzf.lastErr != ReturnCode::BZ_STREAM_END {
        BZ_SETERR!(bzerror, bzf, ReturnCode::BZ_SEQUENCE_ERROR);
        return;
    }

    let (Some(unused), Some(nUnused)) = (unused.as_mut(), nUnused.as_mut()) else {
        BZ_SETERR!(bzerror, bzf, ReturnCode::BZ_PARAM_ERROR);
        return;
    };

    BZ_SETERR!(bzerror, bzf, ReturnCode::BZ_OK);

    *nUnused = bzf.strm.avail_in as c_int;
    *unused = bzf.strm.next_in as *mut c_void;
}

/// Compress the input data into the destination buffer.
///
/// This function attempts to compress the data in `source[0 .. sourceLen]` into `dest[0 .. *destLen]`.
/// If the destination buffer is big enough, `*destLen` is set to the size of the compressed data, and [`BZ_OK`] is returned.
/// If the compressed data won't fit, `*destLen` is unchanged, and [`BZ_OUTBUFF_FULL`] is returned.
///
/// For the meaning of parameters `blockSize100k`, `verbosity` and `workFactor`, see [`BZ2_bzCompressInit`].
///
/// A safe choice for the length of the output buffer is a size 1% larger than the input length,
/// plus 600 extra bytes.
///
/// # Returns
///
/// - [`BZ_PARAM_ERROR`] if any of
///     - `dest.is_null()`
///     - `destLen.is_null()`
///     - `source.is_null()`
///     - `!(1..=9).contains(&blockSize100k)`
///     - `!(0..=4).contains(&verbosity)`
///     - `!(0..=250).contains(&workFactor)`
/// - [`BZ_MEM_ERROR`] if insufficient memory is available
/// - [`BZ_OUTBUFF_FULL`] if the size of the compressed data exceeds `*destLen`
/// - [`BZ_OK`] otherwise
///
/// # Safety
///
/// The caller must guarantee that
///
/// * `destLen` satisfies the requirements of [`pointer::as_mut`]
/// * Either
///     - `dest` is `NULL`
///     - `dest` is writable for `*destLen` bytes
/// * Either
///     - `source` is `NULL`
///     - `source` is readable for `sourceLen`
///
/// [`pointer::as_mut`]: https://doc.rust-lang.org/core/primitive.pointer.html#method.as_mut
#[export_name = prefix!(BZ2_bzBuffToBuffCompress)]
pub unsafe extern "C" fn BZ2_bzBuffToBuffCompress(
    dest: *mut c_char,
    destLen: *mut c_uint,
    source: *mut c_char,
    sourceLen: c_uint,
    blockSize100k: c_int,
    verbosity: c_int,
    workFactor: c_int,
) -> c_int {
    let mut strm: bz_stream = bz_stream::zeroed();

    let Some(destLen) = destLen.as_mut() else {
        return ReturnCode::BZ_PARAM_ERROR as c_int;
    };

    if dest.is_null() || source.is_null() {
        return ReturnCode::BZ_PARAM_ERROR as c_int;
    }

    match BZ2_bzCompressInitHelp(&mut strm, blockSize100k, verbosity, workFactor) {
        ReturnCode::BZ_OK => {}
        ret => return ret as c_int,
    }

    strm.next_in = source;
    strm.next_out = dest;
    strm.avail_in = sourceLen;
    strm.avail_out = *destLen;

    match BZ2_bzCompressHelp(&mut strm, Action::Finish as i32) {
        ReturnCode::BZ_FINISH_OK => {
            BZ2_bzCompressEnd(&mut strm);

            ReturnCode::BZ_OUTBUFF_FULL as c_int
        }
        ReturnCode::BZ_STREAM_END => {
            *destLen = (*destLen).wrapping_sub(strm.avail_out);
            BZ2_bzCompressEnd(&mut strm);

            ReturnCode::BZ_OK as c_int
        }
        error => {
            BZ2_bzCompressEnd(&mut strm);

            error as c_int
        }
    }
}

/// Decompress the input data into the destination buffer.
///
/// This function attempts to decompress the data in `source[0 .. sourceLen]` into `dest[0 .. *destLen]`.
/// If the destination buffer is big enough, `*destLen` is set to the size of the decompressed data, and [`BZ_OK`] is returned.
/// If the decompressed data won't fit, `*destLen` is unchanged, and [`BZ_OUTBUFF_FULL`] is returned.
///
/// For the meaning of parameters `small`, `verbosity`, see [`BZ2_bzDecompressInit`].
///
/// Because the compression ratio of the compressed data cannot be known in advance,
/// there is no easy way to guarantee that the output buffer will be big enough.
/// You may of course make arrangements in your code to record the size of the uncompressed data,
/// but such a mechanism is beyond the scope of this library.
///
/// # Returns
///
/// - [`BZ_PARAM_ERROR`] if any of
///     - `dest.is_null()`
///     - `destLen.is_null()`
///     - `source.is_null()`
///     - `!(0..=1).contains(&small)`
///     - `!(0..=4).contains(&verbosity)`
/// - [`BZ_MEM_ERROR`] if insufficient memory is available
/// - [`BZ_OUTBUFF_FULL`] if the size of the compressed data exceeds `*destLen`
/// - [`BZ_DATA_ERROR`] if a data integrity error is detected in the compressed stream
/// - [`BZ_DATA_ERROR_MAGIC`] if the compressed stream doesn't begin with the right magic bytes
/// - [`BZ_UNEXPECTED_EOF`] if the compressed data ends before the logical end-of-stream was detected
/// - [`BZ_OK`] otherwise
///
/// # Safety
///
/// The caller must guarantee that
///
/// * `destLen` satisfies the requirements of [`pointer::as_mut`]
/// * Either
///     - `dest` is `NULL`
///     - `dest` is writable for `*destLen` bytes
/// * Either
///     - `source` is `NULL`
///     - `source` is readable for `sourceLen`
///
/// [`pointer::as_mut`]: https://doc.rust-lang.org/core/primitive.pointer.html#method.as_mut
#[export_name = prefix!(BZ2_bzBuffToBuffDecompress)]
pub unsafe extern "C" fn BZ2_bzBuffToBuffDecompress(
    dest: *mut c_char,
    destLen: *mut c_uint,
    source: *mut c_char,
    sourceLen: c_uint,
    small: c_int,
    verbosity: c_int,
) -> c_int {
    if dest.is_null() || destLen.is_null() || source.is_null() {
        return ReturnCode::BZ_PARAM_ERROR as c_int;
    }

    let mut strm: bz_stream = bz_stream::zeroed();

    match BZ2_bzDecompressInitHelp(&mut strm, verbosity, small) {
        ReturnCode::BZ_OK => {}
        ret => return ret as c_int,
    }

    strm.next_in = source;
    strm.next_out = dest;
    strm.avail_in = sourceLen;
    strm.avail_out = *destLen;

    match BZ2_bzDecompressHelp(&mut strm) {
        ReturnCode::BZ_OK => {
            BZ2_bzDecompressEnd(&mut strm);

            match strm.avail_out {
                0 => ReturnCode::BZ_OUTBUFF_FULL as c_int,
                _ => ReturnCode::BZ_UNEXPECTED_EOF as c_int,
            }
        }
        ReturnCode::BZ_STREAM_END => {
            *destLen = (*destLen).wrapping_sub(strm.avail_out);
            BZ2_bzDecompressEnd(&mut strm);

            ReturnCode::BZ_OK as c_int
        }
        error => {
            BZ2_bzDecompressEnd(&mut strm);

            error as c_int
        }
    }
}

#[derive(Copy, Clone)]
pub(crate) enum Operation {
    Reading,
    Writing,
}

enum OpenMode {
    Pointer,
    FileDescriptor(i32),
}

unsafe fn bzopen_or_bzdopen(path: Option<&CStr>, open_mode: OpenMode, mode: &CStr) -> *mut BZFILE {
    let mut bzerr = 0;
    let mut unused: [c_char; BZ_MAX_UNUSED as usize] = [0; BZ_MAX_UNUSED as usize];

    let mut blockSize100k = 9;
    let verbosity = 0;
    let workFactor = 30;
    let nUnused = 0;

    let mut smallMode = false;
    let mut operation = Operation::Reading;

    for c in mode.to_bytes() {
        match c {
            b'r' => operation = Operation::Reading,
            b'w' => operation = Operation::Writing,
            b's' => smallMode = true,
            b'0'..=b'9' => blockSize100k = (*c - b'0') as i32,
            _ => {}
        }
    }

    let mode = match open_mode {
        OpenMode::Pointer => match operation {
            Operation::Reading => b"rbe\0".as_slice(),
            Operation::Writing => b"rbe\0".as_slice(),
        },
        OpenMode::FileDescriptor(_) => match operation {
            Operation::Reading => b"rb\0".as_slice(),
            Operation::Writing => b"rb\0".as_slice(),
        },
    };

    let mode_cstr = mode.as_ptr().cast_mut().cast::<c_char>();

    let opt_fp = match open_mode {
        OpenMode::Pointer => match path {
            None => None,
            Some(path) if path.is_empty() => None,
            Some(path) => Some(fopen(path.as_ptr(), mode_cstr)),
        },
        OpenMode::FileDescriptor(fd) => Some(fdopen(fd, mode_cstr)),
    };

    let fp = match opt_fp {
        Some(fp) => fp,
        None => match operation {
            Operation::Reading => fdopen(0, mode_cstr),
            Operation::Writing => fdopen(1, mode_cstr),
        },
    };

    if fp.is_null() {
        return ptr::null_mut();
    }

    let bzfp = match operation {
        Operation::Reading => BZ2_bzReadOpen(
            &mut bzerr,
            fp,
            verbosity,
            smallMode as i32,
            unused.as_mut_ptr() as *mut c_void,
            nUnused,
        ),
        Operation::Writing => BZ2_bzWriteOpen(
            &mut bzerr,
            fp,
            blockSize100k.clamp(1, 9),
            verbosity,
            workFactor,
        ),
    };

    if bzfp.is_null() {
        if let Some(fp) = opt_fp {
            fclose(fp);
        }
        return ptr::null_mut();
    }

    bzfp
}

/// Opens a `.bz2` file for reading or writing using its name. Analogous to [`libc::fopen`].
///
/// # Safety
///
/// The caller must guarantee that
///
/// * Either
///     - `path` is `NULL`
///     - `path` is a null-terminated sequence of bytes
/// * Either
///     - `mode` is `NULL`
///     - `mode` is a null-terminated sequence of bytes
///
/// [`pointer::as_mut`]: https://doc.rust-lang.org/core/primitive.pointer.html#method.as_mut
#[export_name = prefix!(BZ2_bzopen)]
pub unsafe extern "C" fn BZ2_bzopen(path: *const c_char, mode: *const c_char) -> *mut BZFILE {
    let mode = if mode.is_null() {
        return ptr::null_mut();
    } else {
        CStr::from_ptr(mode)
    };

    let path = if path.is_null() {
        None
    } else {
        Some(CStr::from_ptr(path))
    };

    bzopen_or_bzdopen(path, OpenMode::Pointer, mode)
}

/// Opens a `.bz2` file for reading or writing using a pre-existing file descriptor. Analogous to [`libc::fdopen`].
///
/// # Safety
///
/// The caller must guarantee that
///
/// * `fd` must be a valid file descriptor for the duration of [`BZ2_bzdopen`]
/// * Either
///     - `mode` is `NULL`
///     - `mode` is a null-terminated sequence of bytes
///
/// [`pointer::as_mut`]: https://doc.rust-lang.org/core/primitive.pointer.html#method.as_mut
#[export_name = prefix!(BZ2_bzdopen)]
pub unsafe extern "C" fn BZ2_bzdopen(fd: c_int, mode: *const c_char) -> *mut BZFILE {
    let mode = if mode.is_null() {
        return ptr::null_mut();
    } else {
        CStr::from_ptr(mode)
    };

    bzopen_or_bzdopen(None, OpenMode::FileDescriptor(fd), mode)
}

/// Reads up to `len` (uncompressed) bytes from the compressed file `b` into the buffer `buf`.
///
/// Analogous to [`libc::fread`].
///
/// # Returns
///
/// Number of bytes read on success, or `-1` on failure.
///
/// # Safety
///
/// The caller must guarantee that
///
/// * Either
///     - `b` is `NULL`
///     - `b` is initialized with [`BZ2_bzWriteOpen`] or [`BZ2_bzReadOpen`]
/// * Either
///     - `buf` is `NULL`
///     - `buf` is writable for `len` bytes
///
/// [`pointer::as_mut`]: https://doc.rust-lang.org/core/primitive.pointer.html#method.as_mut
#[export_name = prefix!(BZ2_bzread)]
pub unsafe extern "C" fn BZ2_bzread(b: *mut BZFILE, buf: *mut c_void, len: c_int) -> c_int {
    let mut bzerr = 0;

    if (*b).lastErr == ReturnCode::BZ_STREAM_END {
        return 0;
    }
    let nread = BZ2_bzRead(&mut bzerr, b, buf, len);
    if bzerr == 0 || bzerr == ReturnCode::BZ_STREAM_END as i32 {
        nread
    } else {
        -1
    }
}

/// Absorbs `len` bytes from the buffer `buf`, eventually to be compressed and written to the file.
///
/// Analogous to [`libc::fwrite`].
///
/// # Returns
///
/// The value `len` on success, or `-1` on failure.
///
/// # Safety
///
/// The caller must guarantee that
///
/// * Either
///     - `b` is `NULL`
///     - `b` is initialized with [`BZ2_bzWriteOpen`] or [`BZ2_bzReadOpen`]
/// * Either
///     - `buf` is `NULL`
///     - `buf` is readable for `len` bytes
///
/// [`pointer::as_mut`]: https://doc.rust-lang.org/core/primitive.pointer.html#method.as_mut
#[export_name = prefix!(BZ2_bzwrite)]
pub unsafe extern "C" fn BZ2_bzwrite(b: *mut BZFILE, buf: *const c_void, len: c_int) -> c_int {
    let mut bzerr = 0;
    BZ2_bzWrite(&mut bzerr, b, buf, len);

    match bzerr {
        0 => len,
        _ => -1,
    }
}

/// Flushes a [`BZFILE`].
///
/// Analogous to [`libc::fflush`].
///
/// # Safety
///
/// The caller must guarantee that
///
/// * Either
///     - `b` is `NULL`
///     - `b` is initialized with [`BZ2_bzReadOpen`] or [`BZ2_bzWriteOpen`]
#[export_name = prefix!(BZ2_bzflush)]
pub unsafe extern "C" fn BZ2_bzflush(mut _b: *mut BZFILE) -> c_int {
    /* do nothing now... */
    0
}

/// Closes a [`BZFILE`].
///
/// Analogous to [`libc::fclose`].
///
/// # Safety
///
/// The caller must guarantee that
///
/// * Either
///     - `b` is `NULL`
///     - `b` is initialized with [`BZ2_bzReadOpen`] or [`BZ2_bzWriteOpen`]
#[export_name = prefix!(BZ2_bzclose)]
pub unsafe extern "C" fn BZ2_bzclose(b: *mut BZFILE) {
    let mut bzerr: c_int = 0;

    let (fp, operation) = {
        let Some(bzf) = b.as_mut() else {
            return;
        };

        (bzf.handle, bzf.operation)
    };

    match operation {
        Operation::Reading => {
            BZ2_bzReadClose(&mut bzerr, b);
        }
        Operation::Writing => {
            BZ2_bzWriteClose(
                &mut bzerr,
                b,
                false as i32,
                ptr::null_mut(),
                ptr::null_mut(),
            );
            if bzerr != 0 {
                BZ2_bzWriteClose(
                    ptr::null_mut(),
                    b,
                    true as i32,
                    ptr::null_mut(),
                    ptr::null_mut(),
                );
            }
        }
    }

    // don't close stdin or stdout
    if libc::fileno(fp) > 1 {
        fclose(fp);
    }
}

const BZERRORSTRINGS: [&str; 16] = [
    "OK\0",
    "SEQUENCE_ERROR\0",
    "PARAM_ERROR\0",
    "MEM_ERROR\0",
    "DATA_ERROR\0",
    "DATA_ERROR_MAGIC\0",
    "IO_ERROR\0",
    "UNEXPECTED_EOF\0",
    "OUTBUFF_FULL\0",
    "CONFIG_ERROR\0",
    "???\0",
    "???\0",
    "???\0",
    "???\0",
    "???\0",
    "???\0",
];

/// Describes the most recent error.
///
/// # Returns
///
/// A null-terminated string describing the most recent error status of `b`, and also sets `*errnum` to its numerical value.
///
/// # Safety
///
/// The caller must guarantee that
///
/// * Either
///     - `b` is `NULL`
///     - `b` is initialized with [`BZ2_bzReadOpen`] or [`BZ2_bzWriteOpen`]
/// * `errnum` satisfies the requirements of [`pointer::as_mut`]
///
/// [`pointer::as_mut`]: https://doc.rust-lang.org/core/primitive.pointer.html#method.as_mut
#[export_name = prefix!(BZ2_bzerror)]
pub unsafe extern "C" fn BZ2_bzerror(b: *const BZFILE, errnum: *mut c_int) -> *const c_char {
    let err = Ord::min(0, (*(b)).lastErr as c_int);
    if let Some(errnum) = errnum.as_mut() {
        *errnum = err;
    };
    let msg = match BZERRORSTRINGS.get(-err as usize) {
        Some(msg) => msg,
        None => "???\0",
    };
    msg.as_ptr().cast::<c_char>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_messages() {
        let mut bz_file = BZFILE {
            handle: core::ptr::null_mut(),
            buf: [0; 5000],
            bufN: 0,
            strm: bz_stream::zeroed(),
            lastErr: ReturnCode::BZ_OK,
            operation: Operation::Reading,
            initialisedOk: false,
        };

        let return_codes = [
            ReturnCode::BZ_OK,
            ReturnCode::BZ_RUN_OK,
            ReturnCode::BZ_FLUSH_OK,
            ReturnCode::BZ_FINISH_OK,
            ReturnCode::BZ_STREAM_END,
            ReturnCode::BZ_SEQUENCE_ERROR,
            ReturnCode::BZ_PARAM_ERROR,
            ReturnCode::BZ_MEM_ERROR,
            ReturnCode::BZ_DATA_ERROR,
            ReturnCode::BZ_DATA_ERROR_MAGIC,
            ReturnCode::BZ_IO_ERROR,
            ReturnCode::BZ_UNEXPECTED_EOF,
            ReturnCode::BZ_OUTBUFF_FULL,
            ReturnCode::BZ_CONFIG_ERROR,
        ];

        for return_code in return_codes {
            bz_file.lastErr = return_code;

            let mut errnum = 0;
            let ptr = unsafe { BZ2_bzerror(&bz_file as *const BZFILE, &mut errnum) };
            assert!(!ptr.is_null());
            let cstr = unsafe { CStr::from_ptr(ptr) };

            let msg = cstr.to_str().unwrap();

            let expected = match return_code {
                ReturnCode::BZ_OK => "OK",
                ReturnCode::BZ_RUN_OK => "OK",
                ReturnCode::BZ_FLUSH_OK => "OK",
                ReturnCode::BZ_FINISH_OK => "OK",
                ReturnCode::BZ_STREAM_END => "OK",
                ReturnCode::BZ_SEQUENCE_ERROR => "SEQUENCE_ERROR",
                ReturnCode::BZ_PARAM_ERROR => "PARAM_ERROR",
                ReturnCode::BZ_MEM_ERROR => "MEM_ERROR",
                ReturnCode::BZ_DATA_ERROR => "DATA_ERROR",
                ReturnCode::BZ_DATA_ERROR_MAGIC => "DATA_ERROR_MAGIC",
                ReturnCode::BZ_IO_ERROR => "IO_ERROR",
                ReturnCode::BZ_UNEXPECTED_EOF => "UNEXPECTED_EOF",
                ReturnCode::BZ_OUTBUFF_FULL => "OUTBUFF_FULL",
                ReturnCode::BZ_CONFIG_ERROR => "CONFIG_ERROR",
            };

            assert_eq!(msg, expected);

            if (return_code as i32) < 0 {
                assert_eq!(return_code as i32, errnum);
            } else {
                assert_eq!(0, errnum);
            }
        }
    }
}
