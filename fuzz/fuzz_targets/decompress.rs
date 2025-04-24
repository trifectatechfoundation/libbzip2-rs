#![no_main]

use libbz2_rs_sys::{bz_stream, BZ2_bzDecompress, BZ2_bzDecompressEnd, BZ2_bzDecompressInit};
use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(|input: &[u8]| -> Corpus { decompress_help(input) });

fn decompress_help(source: &[u8]) -> Corpus {
    let mut strm: bz_stream = bz_stream::zeroed();

    // Pick either small or fast based on a byte of input data.
    let small = source.get(source.len() / 2).map_or(false, |v| v % 2 == 0);

    let ret = unsafe { BZ2_bzDecompressInit(&mut strm, 0, small as _) };
    assert_eq!(ret, libbz2_rs_sys::BZ_OK);

    // Small enough to hit interesting cases, but large enough to hit the fast path
    let chunk_size = 16;

    // For code coverage (on CI), we want to keep inputs that triggered the error
    // branches, to get an accurate picture of what error paths we actually hit.
    //
    // It helps that on CI we start with a corpus of valid files: a mutation of such an
    // input is not a sequence of random bytes, but rather quite close to correct and
    // hence likely to hit interesting error conditions.
    let invalid_input = if cfg!(feature = "keep-invalid-in-corpus") {
        Corpus::Keep
    } else {
        Corpus::Reject
    };

    let mut output = vec![0u8; source.len()];
    let output_len = output.len() as _;

    strm.next_out = output.as_mut_ptr().cast::<core::ffi::c_char>();
    strm.avail_out = output_len;

    for chunk in source.chunks(chunk_size) {
        strm.next_in = chunk.as_ptr() as *mut core::ffi::c_char;
        strm.avail_in = chunk.len() as _;

        match unsafe { BZ2_bzDecompress(&mut strm) } {
            libbz2_rs_sys::BZ_STREAM_END => {
                break;
            }
            libbz2_rs_sys::BZ_OK => {
                continue;
            }
            libbz2_rs_sys::BZ_FINISH_OK | libbz2_rs_sys::BZ_OUTBUFF_FULL => {
                let add_space: u32 = Ord::max(1024, output.len().try_into().unwrap());
                output.resize(output.len() + add_space as usize, 0);

                // If resize() reallocates, it may have moved in memory.
                strm.next_out = output.as_mut_ptr().cast::<core::ffi::c_char>();
                strm.avail_out += add_space;
            }
            _ => {
                unsafe { BZ2_bzDecompressEnd(&mut strm) };
                return invalid_input;
            }
        }
    }

    let err = unsafe { BZ2_bzDecompressEnd(&mut strm) };
    match err {
        libbz2_rs_sys::BZ_OK => Corpus::Keep,
        _ => invalid_input,
    }
}
