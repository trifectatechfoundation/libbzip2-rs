#![allow(dead_code, unused_imports, unused_macros, non_snake_case)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::manual_c_str_literals)]

use std::{
    ffi::{c_char, c_int, c_void, CStr},
    mem::MaybeUninit,
    path::{Path, PathBuf},
};

mod chunked;

const WB_MODE: *const c_char = b"wb\0".as_ptr().cast::<c_char>();
const RB_MODE: *const c_char = b"rb\0".as_ptr().cast::<c_char>();

type AllocFunc = unsafe extern "C" fn(*mut c_void, c_int, c_int) -> *mut c_void;
type FreeFunc = unsafe extern "C" fn(*mut c_void, *mut c_void) -> ();

const SAMPLE1_REF: &[u8] = include_bytes!("../../tests/input/quick/sample1.ref");
const SAMPLE1_BZ2: &[u8] = include_bytes!("../../tests/input/quick/sample1.bz2");

#[macro_export]
macro_rules! assert_eq_rs_c {
    ($tt:tt) => {{
        #[cfg(not(miri))]
        #[allow(clippy::macro_metavars_in_unsafe)]
        let _ng = unsafe {
            use bzip2_sys::*;
            use compress_c as compress;
            use decompress_c as decompress;

            $tt
        };

        #[allow(clippy::macro_metavars_in_unsafe)]
        let _rs = unsafe {
            use compress_rs as compress;
            use decompress_rs as decompress;
            use libbz2_rs_sys::*;

            $tt
        };

        #[cfg(not(miri))]
        assert_eq!(_rs, _ng);

        _rs
    }};
}

macro_rules! assert_eq_decompress {
    ($input:literal) => {
        let input = include_bytes!($input);

        assert_eq_rs_c!({
            let mut dest = vec![0; 2 * input.len()];
            let mut dest_len = dest.len() as core::ffi::c_uint;

            decompress(
                dest.as_mut_ptr(),
                &mut dest_len,
                input.as_ptr(),
                input.len() as core::ffi::c_uint,
            );

            dest.truncate(dest_len as usize);

            dest
        });
    };
}

macro_rules! assert_eq_compress {
    ($input:literal) => {
        let input = include_bytes!($input);

        assert_eq_rs_c!({
            let mut dest = vec![0; 2 * input.len()];
            let mut dest_len = dest.len() as core::ffi::c_uint;

            compress(
                dest.as_mut_ptr(),
                &mut dest_len,
                input.as_ptr(),
                input.len() as core::ffi::c_uint,
                9,
            );

            dest.truncate(dest_len as usize);

            dest
        });
    };
}

#[test]
fn miri_version() {
    let ptr = libbz2_rs_sys::BZ2_bzlibVersion();
    let cstr = unsafe { core::ffi::CStr::from_ptr(ptr) };
    let string = cstr.to_str().unwrap();

    assert!(string.starts_with("1.1.0"));
}

#[test]
fn miri_buff_to_buff_compress_small() {
    let verbosity = 0;
    let blockSize100k = 9;
    let workFactor = 30;

    let input = b"lang is it ompaad";

    let mut dest = vec![0u8; 1024];
    let mut dest_len = dest.len() as core::ffi::c_uint;

    let err = unsafe {
        libbz2_rs_sys::BZ2_bzBuffToBuffCompress(
            dest.as_mut_ptr().cast::<core::ffi::c_char>(),
            &mut dest_len,
            input.as_ptr() as *mut _,
            input.len() as _,
            blockSize100k,
            verbosity,
            workFactor,
        )
    };

    assert_eq!(err, 0);
}

#[test]
fn buff_to_buff_compress() {
    let verbosity = 0;
    let blockSize100k = 9;
    let workFactor = 30;

    let mut dest = vec![0; 2 * SAMPLE1_REF.len()];
    let mut dest_len = dest.len() as core::ffi::c_uint;

    let err = unsafe {
        libbz2_rs_sys::BZ2_bzBuffToBuffCompress(
            dest.as_mut_ptr().cast::<core::ffi::c_char>(),
            &mut dest_len,
            SAMPLE1_REF.as_ptr() as *mut _,
            SAMPLE1_REF.len() as _,
            blockSize100k,
            verbosity,
            workFactor,
        )
    };

    assert_eq!(err, 0);
}

#[test]
fn buff_to_buff_decompress() {
    let mut dest = vec![0; SAMPLE1_REF.len()];
    let mut dest_len = dest.len() as core::ffi::c_uint;

    let err = unsafe {
        libbz2_rs_sys::BZ2_bzBuffToBuffDecompress(
            dest.as_mut_ptr().cast::<core::ffi::c_char>(),
            &mut dest_len,
            SAMPLE1_BZ2.as_ptr() as *mut _,
            SAMPLE1_BZ2.len() as _,
            0,
            0,
        )
    };

    assert_eq!(err, 0);
}

fn buff_to_buff_decompress_helper(input: &[u8], buffer_size: usize, is_small: bool) {
    let mut dest = vec![0; buffer_size];
    let mut dest_len = dest.len() as core::ffi::c_uint;

    let err = unsafe {
        libbz2_rs_sys::BZ2_bzBuffToBuffDecompress(
            dest.as_mut_ptr().cast::<core::ffi::c_char>(),
            &mut dest_len,
            input.as_ptr() as *mut _,
            input.len() as _,
            is_small as _,
            0,
        )
    };

    assert_eq!(err, 0);
}

#[test]
fn miri_buff_to_buff_decompress_fast() {
    let input: &[u8] = &[
        66u8, 90, 104, 57, 49, 65, 89, 38, 83, 89, 164, 38, 196, 174, 0, 0, 5, 17, 128, 64, 0, 36,
        167, 204, 0, 32, 0, 49, 3, 64, 208, 34, 105, 128, 122, 141, 161, 22, 187, 73, 99, 176, 39,
        11, 185, 34, 156, 40, 72, 82, 19, 98, 87, 0,
    ];

    buff_to_buff_decompress_helper(input, 1024, false)
}

#[test]
fn miri_buff_to_buff_decompress_small() {
    let input: &[u8] = &[
        66u8, 90, 104, 0x39, 49, 65, 89, 38, 83, 89, 164, 38, 196, 174, 0, 0, 5, 17, 128, 64, 0,
        36, 167, 204, 0, 32, 0, 49, 3, 64, 208, 34, 105, 128, 122, 141, 161, 22, 187, 73, 99, 176,
        39, 11, 185, 34, 156, 40, 72, 82, 19, 98, 87, 0,
    ];

    buff_to_buff_decompress_helper(input, 1024, true)
}

#[test]
fn buff_to_buff_decompress_fast_randomized() {
    let input = include_bytes!("../../tests/input/randomized-blocks.bin");

    buff_to_buff_decompress_helper(input, 256 * 1024, false)
}

#[test]
fn buff_to_buff_decompress_small_randomized() {
    let input = include_bytes!("../../tests/input/randomized-blocks.bin");

    buff_to_buff_decompress_helper(input, 256 * 1024, true)
}

#[test]
fn decompress_sample1() {
    assert_eq_decompress!("../../tests/input/quick/sample1.bz2");
}

#[test]
fn decompress_sample2() {
    assert_eq_decompress!("../../tests/input/quick/sample2.bz2");
}

#[test]
fn miri_decompress_sample3() {
    assert_eq_decompress!("../../tests/input/quick/sample3.bz2");
}

#[test]
fn compress_sample1() {
    assert_eq_compress!("../../tests/input/quick/sample1.bz2");
}

#[test]
fn compress_sample2() {
    assert_eq_compress!("../../tests/input/quick/sample2.bz2");
}

#[test]
fn miri_compress_sample3() {
    assert_eq_compress!("../../tests/input/quick/sample3.bz2");
}

pub unsafe fn decompress_c(
    dest: *mut u8,
    dest_len: *mut libc::c_uint,
    source: *const u8,
    source_len: libc::c_uint,
) -> i32 {
    use bzip2_sys::*;

    let mut strm: bz_stream = bz_stream {
        next_in: std::ptr::null_mut::<libc::c_char>(),
        avail_in: 0,
        total_in_lo32: 0,
        total_in_hi32: 0,
        next_out: std::ptr::null_mut::<libc::c_char>(),
        avail_out: 0,
        total_out_lo32: 0,
        total_out_hi32: 0,
        state: std::ptr::null_mut::<libc::c_void>(),
        bzalloc: None,
        bzfree: None,
        opaque: std::ptr::null_mut::<libc::c_void>(),
    };
    let mut ret: libc::c_int;
    if dest.is_null() || dest_len.is_null() || source.is_null() {
        return -(2 as libc::c_int);
    }
    strm.bzalloc = None;
    strm.bzfree = None;
    strm.opaque = std::ptr::null_mut::<libc::c_void>();
    unsafe {
        ret = BZ2_bzDecompressInit(&mut strm, 0, 0);
        if ret != 0 as libc::c_int {
            return ret;
        }
        strm.next_in = source as *mut libc::c_char;
        strm.next_out = dest.cast::<core::ffi::c_char>();
        strm.avail_in = source_len;
        strm.avail_out = *dest_len;
        ret = BZ2_bzDecompress(&mut strm);
        if ret == 0 as libc::c_int {
            if strm.avail_out > 0 as libc::c_int as libc::c_uint {
                BZ2_bzDecompressEnd(&mut strm);
                -(7 as libc::c_int)
            } else {
                BZ2_bzDecompressEnd(&mut strm);
                -(8 as libc::c_int)
            }
        } else if ret != 4 as libc::c_int {
            BZ2_bzDecompressEnd(&mut strm);
            return ret;
        } else {
            *dest_len = (*dest_len).wrapping_sub(strm.avail_out);
            BZ2_bzDecompressEnd(&mut strm);
            return 0 as libc::c_int;
        }
    }
}

pub unsafe fn decompress_rs(
    dest: *mut u8,
    dest_len: *mut libc::c_uint,
    source: *const u8,
    source_len: libc::c_uint,
) -> i32 {
    use libbz2_rs_sys::*;

    let mut strm: bz_stream = bz_stream {
        next_in: std::ptr::null_mut::<libc::c_char>(),
        avail_in: 0,
        total_in_lo32: 0,
        total_in_hi32: 0,
        next_out: std::ptr::null_mut::<libc::c_char>(),
        avail_out: 0,
        total_out_lo32: 0,
        total_out_hi32: 0,
        state: std::ptr::null_mut::<libc::c_void>(),
        bzalloc: None,
        bzfree: None,
        opaque: std::ptr::null_mut::<libc::c_void>(),
    };
    let mut ret: libc::c_int;
    if dest.is_null() || dest_len.is_null() || source.is_null() {
        return -(2 as libc::c_int);
    }
    strm.bzalloc = None;
    strm.bzfree = None;
    strm.opaque = std::ptr::null_mut::<libc::c_void>();
    unsafe {
        ret = BZ2_bzDecompressInit(&mut strm, 0, 0);
        if ret != 0 as libc::c_int {
            return ret;
        }
        strm.next_in = source as *mut libc::c_char;
        strm.next_out = dest.cast::<core::ffi::c_char>();
        strm.avail_in = source_len;
        strm.avail_out = *dest_len;
        ret = BZ2_bzDecompress(&mut strm);
        if ret == 0 as libc::c_int {
            if strm.avail_out > 0 as libc::c_int as libc::c_uint {
                BZ2_bzDecompressEnd(&mut strm);
                -(7 as libc::c_int)
            } else {
                BZ2_bzDecompressEnd(&mut strm);
                -(8 as libc::c_int)
            }
        } else if ret != 4 as libc::c_int {
            BZ2_bzDecompressEnd(&mut strm);
            return ret;
        } else {
            *dest_len = (*dest_len).wrapping_sub(strm.avail_out);
            BZ2_bzDecompressEnd(&mut strm);
            return 0 as libc::c_int;
        }
    }
}

pub unsafe fn compress_c(
    dest: *mut u8,
    dest_len: *mut libc::c_uint,
    source: *const u8,
    source_len: libc::c_uint,
    blockSize100k: i32,
) -> i32 {
    use bzip2_sys::*;

    let mut strm: bz_stream = bz_stream {
        next_in: std::ptr::null_mut::<libc::c_char>(),
        avail_in: 0,
        total_in_lo32: 0,
        total_in_hi32: 0,
        next_out: std::ptr::null_mut::<libc::c_char>(),
        avail_out: 0,
        total_out_lo32: 0,
        total_out_hi32: 0,
        state: std::ptr::null_mut::<libc::c_void>(),
        bzalloc: None,
        bzfree: None,
        opaque: std::ptr::null_mut::<libc::c_void>(),
    };
    if dest.is_null() || dest_len.is_null() || source.is_null() {
        return -2 as libc::c_int;
    }
    strm.bzalloc = None;
    strm.bzfree = None;
    strm.opaque = std::ptr::null_mut::<libc::c_void>();
    unsafe {
        let ret = BZ2_bzCompressInit(&mut strm, blockSize100k, 0, 30);
        if ret != 0 as libc::c_int {
            return ret;
        }
        strm.next_in = source as *mut libc::c_char;
        strm.next_out = dest.cast::<core::ffi::c_char>();
        strm.avail_in = source_len;
        strm.avail_out = *dest_len;
        match BZ2_bzCompress(&mut strm, 2) {
            BZ_FINISH_OK => {
                BZ2_bzCompressEnd(&mut strm);

                BZ_OUTBUFF_FULL
            }
            BZ_STREAM_END => {
                *dest_len = (*dest_len).wrapping_sub(strm.avail_out);
                BZ2_bzCompressEnd(&mut strm);

                BZ_OK
            }
            ret => {
                BZ2_bzCompressEnd(&mut strm);

                ret
            }
        }
    }
}

pub unsafe fn compress_rs(
    dest: *mut u8,
    dest_len: *mut libc::c_uint,
    source: *const u8,
    source_len: libc::c_uint,
    blockSize100k: i32,
) -> i32 {
    use libbz2_rs_sys::*;

    let mut strm: bz_stream = bz_stream {
        next_in: std::ptr::null_mut::<libc::c_char>(),
        avail_in: 0,
        total_in_lo32: 0,
        total_in_hi32: 0,
        next_out: std::ptr::null_mut::<libc::c_char>(),
        avail_out: 0,
        total_out_lo32: 0,
        total_out_hi32: 0,
        state: std::ptr::null_mut::<libc::c_void>(),
        bzalloc: None,
        bzfree: None,
        opaque: std::ptr::null_mut::<libc::c_void>(),
    };
    if dest.is_null() || dest_len.is_null() || source.is_null() {
        return -2 as libc::c_int;
    }
    strm.bzalloc = None;
    strm.bzfree = None;
    strm.opaque = std::ptr::null_mut::<libc::c_void>();
    unsafe {
        let ret = BZ2_bzCompressInit(&mut strm, blockSize100k, 0, 30);
        if ret != 0 as libc::c_int {
            return ret;
        }
        strm.next_in = source as *mut libc::c_char;
        strm.next_out = dest.cast::<core::ffi::c_char>();
        strm.avail_in = source_len;
        strm.avail_out = *dest_len;
        match BZ2_bzCompress(&mut strm, 2) {
            BZ_FINISH_OK => {
                BZ2_bzCompressEnd(&mut strm);

                BZ_OUTBUFF_FULL
            }
            BZ_STREAM_END => {
                *dest_len = (*dest_len).wrapping_sub(strm.avail_out);
                BZ2_bzCompressEnd(&mut strm);

                BZ_OK
            }
            ret => {
                BZ2_bzCompressEnd(&mut strm);

                ret
            }
        }
    }
}

#[rustfmt::skip]
mod bzip2_testfiles {
    #![allow(non_snake_case)]

    use super::*;

    #[test] fn miri_pyflate_765B() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/pyflate/765B.bz2"); }
    #[test] fn pyflate_45MB_00() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/pyflate/45MB-00.bz2"); }
    #[test] fn miri_pyflate_hello_world() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/pyflate/hello-world.bz2"); }
    #[test] fn miri_pyflate_510B() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/pyflate/510B.bz2"); }
    #[test] fn miri_pyflate_aaa() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/pyflate/aaa.bz2"); }
    #[test] fn miri_pyflate_empty() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/pyflate/empty.bz2"); }
    #[test] fn pyflate_45MB_fb() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/pyflate/45MB-fb.bz2"); }
    #[test] fn miri_commons_compress_bla_xml() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/commons-compress/bla.xml.bz2"); }
    #[test] fn miri_commons_compress_bla_tar() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/commons-compress/bla.tar.bz2"); }
    #[test] fn miri_commons_compress_bla_txt() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/commons-compress/bla.txt.bz2"); }
    #[test] fn miri_commons_compress_COMPRESS_131() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/commons-compress/COMPRESS-131.bz2"); }
    #[test] fn miri_commons_compress_multiple() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/commons-compress/multiple.bz2"); }
    #[test] fn commons_compress_zip64support() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/commons-compress/zip64support.tar.bz2"); }
    #[test] fn go_compress_e() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/go/compress/e.txt.bz2"); }
    #[test] fn go_compress_Isaac() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/go/compress/Isaac.Newton-Opticks.txt.bz2"); }
    #[test] fn go_compress_pass_sawtooth() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/go/compress/pass-sawtooth.bz2"); }
    #[test] fn go_compress_pass_random1() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/go/compress/pass-random1.bz2"); }
    #[test] fn go_compress_pass_random2() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/go/compress/pass-random2.bz2"); }
    #[test] fn go_compress_random() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/go/compress/random.data.bz2"); }
    #[test] fn go_regexp_re2_exhaustive() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/go/regexp/re2-exhaustive.txt.bz2"); }
    #[test] fn go_crypto_pss_vect() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/go/crypto/pss-vect.txt.bz2"); }
    #[test] fn go_crypto_SigVer() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/go/crypto/SigVer.rsp.bz2"); }
    #[test] fn miri_lbzip2_incomp_1() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/lbzip2/incomp-1.bz2"); }
    #[test] fn miri_lbzip2_trash() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/lbzip2/trash.bz2"); }
    #[test] fn miri_lbzip2_incomp_2() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/lbzip2/incomp-2.bz2"); }
    #[test] fn lbzip2_fib() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/lbzip2/fib.bz2"); }
    #[test] fn lbzip2_ch255() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/lbzip2/ch255.bz2"); }
    #[test] fn lbzip2_32767() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/lbzip2/32767.bz2"); }
    #[test] fn miri_lbzip2_empty() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/lbzip2/empty.bz2"); }
    #[test] fn miri_lbzip2_concat() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/lbzip2/concat.bz2"); }
    #[test] fn lbzip2_idx899999() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/lbzip2/idx899999.bz2"); }
    #[test] fn lbzip2_repet() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/lbzip2/repet.bz2"); }
    #[test] fn miri_lbzip2_codelen20() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/lbzip2/codelen20.bz2"); }
    #[test] fn miri_lbzip2_gap() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/lbzip2/gap.bz2"); }
    #[test] fn miri_lbzip2_rand() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/lbzip2/rand.bz2"); }
    #[test] fn dotnetzip_sample1() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/dotnetzip/sample1.bz2"); }
    #[test] fn dotnetzip_sample2() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/dotnetzip/sample2.bz2"); }
    #[test] fn dotnetzip_dancing_color() { assert_eq_decompress!("../../tests/input/bzip2-testfiles/dotnetzip/dancing-color.ps.bz2"); }
}

#[test]
fn miri_decompress_init_edge_cases() {
    // valid input
    crate::assert_eq_rs_c!({
        let mut strm = MaybeUninit::zeroed();
        assert_eq!(BZ_OK, BZ2_bzDecompressInit(strm.as_mut_ptr(), 0, 0));
        BZ2_bzDecompressEnd(strm.as_mut_ptr())
    });

    // strm is NULL
    crate::assert_eq_rs_c!({
        assert_eq!(
            BZ_PARAM_ERROR,
            BZ2_bzDecompressInit(core::ptr::null_mut(), 0, 0)
        );
    });

    // verbosity is out of range
    crate::assert_eq_rs_c!({
        let mut strm = MaybeUninit::zeroed();
        assert_eq!(
            BZ_PARAM_ERROR,
            BZ2_bzDecompressInit(strm.as_mut_ptr(), 42, 0)
        );
    });

    // small is out of range
    crate::assert_eq_rs_c!({
        let mut strm = MaybeUninit::zeroed();
        assert_eq!(
            BZ_PARAM_ERROR,
            BZ2_bzDecompressInit(strm.as_mut_ptr(), 0, 42)
        );
    });

    unsafe extern "C" fn failing_allocator(
        _opaque: *mut c_void,
        _items: i32,
        _size: i32,
    ) -> *mut c_void {
        core::ptr::null_mut()
    }

    unsafe extern "C" fn dummy_free(_opaque: *mut c_void, _ptr: *mut c_void) {}

    // fails to allocate
    crate::assert_eq_rs_c!({
        let mut strm: MaybeUninit<bz_stream> = MaybeUninit::zeroed();

        core::ptr::addr_of_mut!((*strm.as_mut_ptr()).bzalloc)
            .cast::<AllocFunc>()
            .write(failing_allocator);
        core::ptr::addr_of_mut!((*strm.as_mut_ptr()).bzfree)
            .cast::<FreeFunc>()
            .write(dummy_free);

        assert_eq!(BZ_MEM_ERROR, BZ2_bzDecompressInit(strm.as_mut_ptr(), 0, 0));
    });
}

#[test]
fn miri_decompress_edge_cases() {
    // strm is NULL
    crate::assert_eq_rs_c!({
        assert_eq!(BZ_PARAM_ERROR, BZ2_bzDecompress(core::ptr::null_mut()));
    });

    // state is NULL
    crate::assert_eq_rs_c!({
        let mut strm = MaybeUninit::zeroed();
        assert_eq!(BZ_OK, BZ2_bzDecompressInit(strm.as_mut_ptr(), 0, 0));
        let strm = strm.assume_init_mut();

        let mut state = core::ptr::null_mut();
        core::mem::swap(&mut strm.state, &mut state);
        assert_eq!(BZ_PARAM_ERROR, BZ2_bzDecompress(strm));
        core::mem::swap(&mut strm.state, &mut state);

        BZ2_bzDecompressEnd(strm)
    });

    let input: &[u8] = &[
        66u8, 90, 104, 57, 49, 65, 89, 38, 83, 89, 164, 38, 196, 174, 0, 0, 5, 17, 128, 64, 0, 36,
        167, 204, 0, 32, 0, 49, 3, 64, 208, 34, 105, 128, 122, 141, 161, 22, 187, 73, 99, 176, 39,
        11, 185, 34, 156, 40, 72, 82, 19, 98, 87, 0,
    ];

    // coverage of the log branches
    crate::assert_eq_rs_c!({
        let mut strm = MaybeUninit::zeroed();
        assert_eq!(BZ_OK, BZ2_bzDecompressInit(strm.as_mut_ptr(), 4, 0));
        let strm = strm.assume_init_mut();

        let mut output = [0u8; 64];

        strm.avail_in = input.len() as _;
        strm.next_in = input.as_ptr().cast_mut().cast();

        strm.avail_out = output.len() as _;
        strm.next_out = output.as_mut_ptr().cast();

        assert_eq!(BZ_STREAM_END, BZ2_bzDecompress(strm));

        BZ2_bzDecompressEnd(strm)
    });

    // next_in is NULL
    crate::assert_eq_rs_c!({
        let mut strm = MaybeUninit::zeroed();
        assert_eq!(BZ_OK, BZ2_bzDecompressInit(strm.as_mut_ptr(), 4, 0));
        let strm = strm.assume_init_mut();

        let mut output = [0u8; 64];

        strm.avail_in = 0;
        strm.next_in = core::ptr::null_mut();

        strm.avail_out = output.len() as _;
        strm.next_out = output.as_mut_ptr().cast();

        assert_eq!(BZ_OK, BZ2_bzDecompress(strm));

        BZ2_bzDecompressEnd(strm)
    });

    // next_out is NULL
    crate::assert_eq_rs_c!({
        let mut strm = MaybeUninit::zeroed();
        assert_eq!(BZ_OK, BZ2_bzDecompressInit(strm.as_mut_ptr(), 4, 0));
        let strm = strm.assume_init_mut();

        strm.avail_in = input.len() as _;
        strm.next_in = input.as_ptr().cast_mut().cast();

        strm.avail_out = 0;
        strm.next_out = core::ptr::null_mut();

        assert_eq!(BZ_OK, BZ2_bzDecompress(strm));

        BZ2_bzDecompressEnd(strm)
    });
}

#[test]
fn miri_decompress_end_edge_cases() {
    // strm is NULL
    crate::assert_eq_rs_c!({
        assert_eq!(BZ_PARAM_ERROR, BZ2_bzDecompressEnd(core::ptr::null_mut()));
    });

    // state is NULL
    crate::assert_eq_rs_c!({
        let mut strm = MaybeUninit::zeroed();
        assert_eq!(BZ_OK, BZ2_bzDecompressInit(strm.as_mut_ptr(), 0, 0));
        let strm = strm.assume_init_mut();

        let mut state = core::ptr::null_mut();

        core::mem::swap(&mut strm.state, &mut state);
        BZ2_bzDecompressEnd(strm);
        core::mem::swap(&mut strm.state, &mut state);

        BZ2_bzDecompressEnd(strm)
    });

    // bzfree is NULL
    unsafe {
        use libbz2_rs_sys::*;

        let mut strm = MaybeUninit::zeroed();
        assert_eq!(BZ_OK, BZ2_bzDecompressInit(strm.as_mut_ptr(), 0, 0));
        let strm = strm.assume_init_mut();

        let bzfree = strm.bzfree.take();

        assert_eq!(BZ_PARAM_ERROR, BZ2_bzDecompressEnd(strm));

        strm.bzfree = bzfree;
        assert_eq!(BZ_OK, BZ2_bzDecompressEnd(strm));
    }
}

#[test]
fn miri_compress_init_edge_cases() {
    let blockSize100k = 9;
    let verbosity = 0;
    let workFactor = 30;

    // valid input
    crate::assert_eq_rs_c!({
        let mut strm = MaybeUninit::zeroed();
        assert_eq!(
            BZ_OK,
            BZ2_bzCompressInit(strm.as_mut_ptr(), blockSize100k, verbosity, workFactor)
        );
        BZ2_bzCompressEnd(strm.as_mut_ptr())
    });

    // strm is NULL
    crate::assert_eq_rs_c!({
        assert_eq!(
            BZ_PARAM_ERROR,
            BZ2_bzCompressInit(core::ptr::null_mut(), blockSize100k, verbosity, workFactor)
        );
    });

    // blockSize100k is out of range
    crate::assert_eq_rs_c!({
        let mut strm = MaybeUninit::zeroed();
        assert_eq!(
            BZ_PARAM_ERROR,
            BZ2_bzCompressInit(strm.as_mut_ptr(), 123, verbosity, workFactor)
        );
    });

    // interestingly, an out-of-range verbosity is OK
    crate::assert_eq_rs_c!({
        let mut strm = MaybeUninit::zeroed();
        assert_eq!(
            BZ_OK,
            BZ2_bzCompressInit(strm.as_mut_ptr(), blockSize100k, 123, workFactor)
        );
        BZ2_bzCompressEnd(strm.as_mut_ptr())
    });

    // workFactor
    crate::assert_eq_rs_c!({
        let mut strm = MaybeUninit::zeroed();
        assert_eq!(
            BZ_PARAM_ERROR,
            BZ2_bzCompressInit(strm.as_mut_ptr(), blockSize100k, verbosity, 251)
        );
    });

    // workFactor of 0 picks the default work factor
    crate::assert_eq_rs_c!({
        let mut strm = MaybeUninit::zeroed();
        assert_eq!(
            BZ_OK,
            BZ2_bzCompressInit(strm.as_mut_ptr(), blockSize100k, verbosity, 0)
        );
        BZ2_bzCompressEnd(strm.as_mut_ptr())
    });

    // allocation failures
    crate::assert_eq_rs_c!({
        use core::sync::atomic::{AtomicUsize, Ordering};

        static TOTAL_BUDGET: AtomicUsize = AtomicUsize::new(0);
        static BUDGET: AtomicUsize = AtomicUsize::new(0);

        unsafe extern "C" fn failing_allocator(
            _opaque: *mut c_void,
            items: i32,
            size: i32,
        ) -> *mut c_void {
            let extra = (items * size) as usize;

            if extra <= BUDGET.load(Ordering::Relaxed) {
                BUDGET.fetch_sub(extra, Ordering::Relaxed);

                libc::malloc((items * size) as usize)
            } else {
                let total = TOTAL_BUDGET.fetch_add(extra, Ordering::Relaxed);
                BUDGET.store(total + extra, Ordering::Relaxed);
                core::ptr::null_mut()
            }
        }

        unsafe extern "C" fn deallocate(_opaque: *mut c_void, ptr: *mut c_void) {
            if !ptr.is_null() {
                libc::free(ptr);
            }
        }

        for _ in 0..4 {
            let mut strm: MaybeUninit<bz_stream> = MaybeUninit::zeroed();

            core::ptr::addr_of_mut!((*strm.as_mut_ptr()).bzalloc)
                .cast::<AllocFunc>()
                .write(failing_allocator);

            core::ptr::addr_of_mut!((*strm.as_mut_ptr()).bzfree)
                .cast::<FreeFunc>()
                .write(deallocate);

            assert_eq!(
                BZ_MEM_ERROR,
                BZ2_bzCompressInit(strm.as_mut_ptr(), blockSize100k, verbosity, workFactor)
            );
        }
    });
}

#[test]
fn miri_compress_edge_cases() {
    let blockSize100k = 9;
    let verbosity = 0;
    let workFactor = 30;

    // strm is NULL
    crate::assert_eq_rs_c!({
        assert_eq!(
            BZ_PARAM_ERROR,
            BZ2_bzCompress(core::ptr::null_mut(), BZ_FINISH)
        );
    });

    // state is NULL
    crate::assert_eq_rs_c!({
        let mut strm = MaybeUninit::zeroed();
        assert_eq!(
            BZ_OK,
            BZ2_bzCompressInit(strm.as_mut_ptr(), blockSize100k, verbosity, workFactor)
        );
        let strm = strm.assume_init_mut();

        let mut state = core::ptr::null_mut();
        core::mem::swap(&mut strm.state, &mut state);
        assert_eq!(BZ_PARAM_ERROR, BZ2_bzCompress(strm, 2));
        core::mem::swap(&mut strm.state, &mut state);

        BZ2_bzCompressEnd(strm)
    });

    // action out of bounds
    crate::assert_eq_rs_c!({
        let mut strm = MaybeUninit::zeroed();
        assert_eq!(
            BZ_OK,
            BZ2_bzCompressInit(strm.as_mut_ptr(), blockSize100k, 4, workFactor)
        );
        let strm = strm.assume_init_mut();

        let input: &[u8] = b"lang is it ompaad";

        let mut output = [0u8; 64];

        strm.avail_in = input.len() as _;
        strm.next_in = input.as_ptr().cast_mut().cast();

        strm.avail_out = output.len() as _;
        strm.next_out = output.as_mut_ptr().cast();

        assert_eq!(BZ_PARAM_ERROR, BZ2_bzCompress(strm, 42));

        BZ2_bzCompressEnd(strm);

        output
    });

    // coverage of the log branches
    crate::assert_eq_rs_c!({
        let mut strm = MaybeUninit::zeroed();
        assert_eq!(
            BZ_OK,
            BZ2_bzCompressInit(strm.as_mut_ptr(), blockSize100k, 4, workFactor)
        );
        let strm = strm.assume_init_mut();

        let input: &[u8] = b"lang is it ompaad";

        let mut output = [0u8; 64];

        strm.avail_in = input.len() as _;
        strm.next_in = input.as_ptr().cast_mut().cast();

        strm.avail_out = output.len() as _;
        strm.next_out = output.as_mut_ptr().cast();

        assert_eq!(BZ_STREAM_END, BZ2_bzCompress(strm, 2));

        BZ2_bzCompressEnd(strm);

        output
    });

    let mut output = [0u8; 64];

    // avail_in is NULL
    crate::assert_eq_rs_c!({
        let mut strm = MaybeUninit::zeroed();
        assert_eq!(
            BZ_OK,
            BZ2_bzCompressInit(strm.as_mut_ptr(), blockSize100k, verbosity, workFactor)
        );
        let strm = strm.assume_init_mut();

        strm.avail_in = 0;
        strm.next_in = core::ptr::null_mut();

        strm.avail_out = output.len() as _;
        strm.next_out = output.as_mut_ptr().cast();

        assert_eq!(BZ_STREAM_END, BZ2_bzCompress(strm, 2));

        BZ2_bzCompressEnd(strm);

        output
    });

    // avail_out is NULL
    crate::assert_eq_rs_c!({
        let mut strm = MaybeUninit::zeroed();
        assert_eq!(
            BZ_OK,
            BZ2_bzCompressInit(strm.as_mut_ptr(), blockSize100k, verbosity, workFactor)
        );
        let strm = strm.assume_init_mut();

        let input: &[u8] = b"lang is it ompaad";

        strm.avail_in = input.len() as _;
        strm.next_in = input.as_ptr().cast_mut().cast();

        strm.avail_out = 0;
        strm.next_out = core::ptr::null_mut();

        assert_eq!(BZ_FINISH_OK, BZ2_bzCompress(strm, 2));

        BZ2_bzCompressEnd(strm);
    });

    crate::assert_eq_rs_c!({
        let mut strm = MaybeUninit::zeroed();
        assert_eq!(
            BZ_OK,
            BZ2_bzCompressInit(strm.as_mut_ptr(), blockSize100k, verbosity, workFactor)
        );
        let strm = strm.assume_init_mut();

        let input: &[u8] = b"lang is it ompaad";

        strm.avail_in = 0;
        strm.next_in = input.as_ptr().cast_mut().cast();

        strm.avail_out = 0;
        strm.next_out = output.as_mut_ptr().cast();

        assert_eq!(BZ_SEQUENCE_ERROR, BZ2_bzCompress(strm, BZ_FINISH));

        BZ2_bzCompressEnd(strm);

        output
    });
}

#[test]
fn miri_compress_64_bit_arithmetic_edge_cases() {
    let mut output = [0u8; 64];

    let blockSize100k = 9;
    let verbosity = 0;
    let workFactor = 30;

    // 32-bit overflow for the running state
    crate::assert_eq_rs_c!({
        let mut strm = MaybeUninit::zeroed();
        assert_eq!(
            BZ_OK,
            BZ2_bzCompressInit(strm.as_mut_ptr(), blockSize100k, verbosity, workFactor)
        );
        let strm = strm.assume_init_mut();

        let input: &[u8] = b"lang is it ompaad";

        strm.avail_in = input.len() as _;
        strm.next_in = input.as_ptr().cast_mut().cast();

        strm.avail_out = output.len() as _;
        strm.next_out = output.as_mut_ptr().cast();

        strm.total_in_lo32 = u32::MAX - 5;
        strm.total_out_lo32 = u32::MAX - 5;

        assert_eq!(BZ_RUN_OK, BZ2_bzCompress(strm, BZ_RUN));

        let total_in = ((strm.total_in_hi32 as u64) << 32) | strm.total_in_lo32 as u64;
        assert_eq!(total_in, u32::MAX as u64 - 5 + input.len() as u64);

        assert_eq!(BZ_STREAM_END, BZ2_bzCompress(strm, BZ_FINISH));

        const OUTPUT_SIZE: u64 = 54;

        let total_out = ((strm.total_out_hi32 as u64) << 32) | strm.total_out_lo32 as u64;
        assert_eq!(total_out, u32::MAX as u64 - 5 + OUTPUT_SIZE);

        BZ2_bzCompressEnd(strm);

        output
    });

    // 32-bit overflow for the flushing state
    crate::assert_eq_rs_c!({
        let mut strm = MaybeUninit::zeroed();
        assert_eq!(
            BZ_OK,
            BZ2_bzCompressInit(strm.as_mut_ptr(), blockSize100k, verbosity, workFactor)
        );
        let strm = strm.assume_init_mut();

        let input: &[u8] = b"lang is it ompaad";

        strm.next_in = input.as_ptr().cast_mut().cast();
        strm.next_out = output.as_mut_ptr().cast();

        let (first_chunk, second_chunk) = (input.len() - 5, 5);

        strm.avail_in = first_chunk as _;
        strm.avail_out = 4;

        strm.total_in_lo32 = u32::MAX - strm.avail_in;
        strm.total_out_lo32 = u32::MAX;

        assert_eq!(BZ_RUN_OK, BZ2_bzCompress(strm, BZ_RUN));

        strm.avail_out = 60;
        strm.avail_in = second_chunk;
        assert_eq!(BZ_RUN_OK, BZ2_bzCompress(strm, BZ_FLUSH));

        let total_in = ((strm.total_in_hi32 as u64) << 32) | strm.total_in_lo32 as u64;
        assert_eq!(total_in, u32::MAX as u64 + second_chunk as u64);

        assert_eq!(BZ_STREAM_END, BZ2_bzCompress(strm, BZ_FINISH));

        const OUTPUT_SIZE: u64 = 54;

        let total_out = ((strm.total_out_hi32 as u64) << 32) | strm.total_out_lo32 as u64;
        assert_eq!(total_out, u32::MAX as u64 + OUTPUT_SIZE);

        BZ2_bzCompressEnd(strm);

        output
    });
}

#[test]
fn miri_compress_action_edge_cases() {
    let mut output = [0u8; 64];

    let blockSize100k = 9;
    let verbosity = 0;
    let workFactor = 30;

    // flush action
    crate::assert_eq_rs_c!({
        let mut strm = MaybeUninit::zeroed();
        assert_eq!(
            BZ_OK,
            BZ2_bzCompressInit(strm.as_mut_ptr(), blockSize100k, verbosity, workFactor)
        );
        let strm = strm.assume_init_mut();

        let input: &[u8] = b"lang is it ompaad";

        strm.avail_in = input.len() as _;
        strm.next_in = input.as_ptr().cast_mut().cast();

        strm.avail_out = 0;
        strm.next_out = core::ptr::null_mut();

        strm.next_out = output.as_mut_ptr().cast();

        strm.avail_out = 4;
        assert_eq!(BZ_RUN_OK, BZ2_bzCompress(strm, BZ_RUN));

        // do some (but not all) flushing
        strm.avail_out = 4;
        assert_eq!(BZ_FLUSH_OK, BZ2_bzCompress(strm, BZ_FLUSH));

        // now performing a non-flush action errors
        assert_eq!(BZ_SEQUENCE_ERROR, BZ2_bzCompress(strm, BZ_RUN));

        // also messing with the `avail_in` causes an error
        strm.avail_in += 1;
        assert_eq!(BZ_SEQUENCE_ERROR, BZ2_bzCompress(strm, BZ_FLUSH));
        strm.avail_in -= 1;

        // flush the remainder
        strm.avail_out = 64 - 4 - 4;
        assert_eq!(BZ_RUN_OK, BZ2_bzCompress(strm, BZ_FLUSH));

        // process the remainder of the input, write it all to the output
        assert_eq!(BZ_STREAM_END, BZ2_bzCompress(strm, BZ_FINISH));

        // hits the idle SEQUENCE_ERROR case
        assert_eq!(BZ_SEQUENCE_ERROR, BZ2_bzCompress(strm, BZ_RUN));

        BZ2_bzCompressEnd(strm);

        output
    });
}

#[test]
fn miri_compress_end_edge_cases() {
    let blockSize100k = 9;
    let verbosity = 0;
    let workFactor = 30;

    // strm is NULL
    crate::assert_eq_rs_c!({
        assert_eq!(BZ_PARAM_ERROR, BZ2_bzCompressEnd(core::ptr::null_mut()));
    });

    // state is NULL
    crate::assert_eq_rs_c!({
        let mut strm = MaybeUninit::zeroed();
        assert_eq!(
            BZ_OK,
            BZ2_bzCompressInit(strm.as_mut_ptr(), blockSize100k, verbosity, workFactor)
        );
        let strm = strm.assume_init_mut();

        let mut state = core::ptr::null_mut();

        core::mem::swap(&mut strm.state, &mut state);
        BZ2_bzCompressEnd(strm);
        core::mem::swap(&mut strm.state, &mut state);

        BZ2_bzCompressEnd(strm)
    });

    // bzfree is NULL
    unsafe {
        use libbz2_rs_sys::*;

        let mut strm = MaybeUninit::zeroed();
        assert_eq!(
            BZ_OK,
            BZ2_bzCompressInit(strm.as_mut_ptr(), blockSize100k, verbosity, workFactor)
        );
        let strm = strm.assume_init_mut();

        let bzfree = strm.bzfree.take();

        assert_eq!(BZ_PARAM_ERROR, BZ2_bzCompressEnd(strm));

        strm.bzfree = bzfree;
        assert_eq!(BZ_OK, BZ2_bzCompressEnd(strm));
    }
}

#[cfg(not(miri))]
mod high_level_interface {
    use super::*;

    #[test]
    fn high_level_read() {
        use libbz2_rs_sys::*;

        let p = std::env::current_dir().unwrap();

        let input = std::fs::read(p.join("../tests/input/quick/sample1.bz2")).unwrap();
        let mut expected = vec![0u8; 256 * 1024];
        let mut expected_len = expected.len() as _;
        let err = unsafe {
            decompress_c(
                expected.as_mut_ptr(),
                &mut expected_len,
                input.as_ptr(),
                input.len() as _,
            )
        };
        assert_eq!(err, 0);

        let p = p.join("../tests/input/quick/sample1.bz2\0");
        let input_file = unsafe {
            libc::fopen(
                p.display().to_string().as_mut_ptr().cast::<c_char>(),
                RB_MODE,
            )
        };

        assert!(!input_file.is_null());

        let mut bzerror = 0;
        let bz_file =
            unsafe { BZ2_bzReadOpen(&mut bzerror, input_file, 0, 0, core::ptr::null_mut(), 0) };

        let mut output = Vec::<u8>::with_capacity(1024);

        const BUFFER_SIZE: usize = 1024;
        let mut buffer = [0u8; BUFFER_SIZE];
        while bzerror == 0 {
            let bytes_read = unsafe {
                BZ2_bzRead(
                    &mut bzerror,
                    bz_file,
                    buffer.as_mut_ptr().cast(),
                    BUFFER_SIZE as i32,
                )
            };

            if bzerror == BZ_OK || bzerror == BZ_STREAM_END {
                output.extend(&buffer[..bytes_read as usize]);
            }
        }

        // make sure to clean up resources even if there was an error
        let after_read = bzerror;

        unsafe { BZ2_bzReadClose(&mut bzerror, bz_file) };

        unsafe { libc::fclose(input_file) };

        assert_eq!(after_read, BZ_STREAM_END);

        assert_eq!(bzerror, BZ_OK);

        assert_eq!(&expected[..expected_len as usize], output);
    }

    #[test]
    fn high_level_write() {
        use libbz2_rs_sys::*;

        let block_size = 9; // Maximum compression level (1-9)
        let verbosity = 0; // Quiet operation
        let work_factor = 30; // Recommended default value

        let p = std::env::temp_dir().join("high_level_write.bz2");

        let _ = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(&p)
            .unwrap();

        let output_file = unsafe {
            let p = p.with_extension("bz2\0");
            libc::fopen(
                p.display().to_string().as_mut_ptr().cast::<c_char>(),
                WB_MODE,
            )
        };

        assert!(!output_file.is_null());

        let mut bzerror = 0;
        let bz_file = unsafe {
            BZ2_bzWriteOpen(
                &mut bzerror,
                output_file,
                block_size,
                verbosity,
                work_factor,
            )
        };

        for chunk in SAMPLE1_BZ2.chunks(1024) {
            unsafe {
                BZ2_bzWrite(
                    &mut bzerror,
                    bz_file,
                    chunk.as_ptr().cast_mut().cast(),
                    chunk.len() as _,
                )
            };
            assert_eq!(bzerror, 0);
        }

        unsafe {
            BZ2_bzWriteClose(
                &mut bzerror,
                bz_file,
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };

        unsafe { libc::fclose(output_file) };

        assert_eq!(bzerror, BZ_OK);

        let mut expected = vec![0u8; 256 * 1024];
        let mut expected_len = expected.len() as _;
        let err = unsafe {
            compress_c(
                expected.as_mut_ptr(),
                &mut expected_len,
                SAMPLE1_BZ2.as_ptr(),
                SAMPLE1_BZ2.len() as _,
                9,
            )
        };
        assert_eq!(err, 0);

        assert_eq!(
            std::fs::read(p).unwrap(),
            &expected[..expected_len as usize]
        );
    }

    #[test]
    fn test_bzflush() {
        assert_eq!(
            unsafe { libbz2_rs_sys::BZ2_bzflush(core::ptr::null_mut()) },
            0
        );
    }

    #[test]
    #[cfg(unix)]
    fn open_and_close() {
        use std::os::fd::{AsRawFd, IntoRawFd};

        let p = std::env::temp_dir().join("open_and_close.bz2");

        // make sure this branch is hit
        unsafe { libbz2_rs_sys::BZ2_bzclose(core::ptr::null_mut()) };

        let open_file = || {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .truncate(true)
                .create(true)
                .open(&p)
                .unwrap()
        };

        {
            let file = open_file();

            let ptr = unsafe { libbz2_rs_sys::BZ2_bzdopen(file.as_raw_fd(), core::ptr::null()) };
            assert!(ptr.is_null());
        }

        {
            let file = open_file();

            let ptr = unsafe { libbz2_rs_sys::BZ2_bzdopen(file.into_raw_fd(), RB_MODE) };
            assert!(!ptr.is_null());
            unsafe { libbz2_rs_sys::BZ2_bzclose(ptr) };
        }

        {
            let file = open_file();

            let ptr = unsafe { libbz2_rs_sys::BZ2_bzdopen(file.into_raw_fd(), WB_MODE) };
            assert!(!ptr.is_null());
            unsafe { libbz2_rs_sys::BZ2_bzclose(ptr) };
        }

        let path_as_cstring = p.with_extension("bz2\0").display().to_string();

        {
            let path = path_as_cstring.as_ptr().cast();
            let ptr = unsafe { libbz2_rs_sys::BZ2_bzopen(path, RB_MODE) };
            assert!(!ptr.is_null());
            unsafe { libbz2_rs_sys::BZ2_bzclose(ptr) };
        }

        {
            let path = path_as_cstring.as_ptr().cast();
            let ptr = unsafe { libbz2_rs_sys::BZ2_bzopen(path, WB_MODE) };
            assert!(!ptr.is_null());
            unsafe { libbz2_rs_sys::BZ2_bzclose(ptr) };
        }

        // so it does not get dropped prematurely
        drop(path_as_cstring);
    }
}
