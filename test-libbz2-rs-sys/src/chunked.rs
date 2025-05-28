use crate::{compress_c, decompress_c, SAMPLE1_BZ2, SAMPLE1_REF};

fn decompress_rs_chunked_input<'a>(
    dest: &'a mut [u8],
    source: &[u8],
    chunk_size: usize,
) -> Result<&'a mut [u8], i32> {
    use libbz2_rs_sys::*;

    let mut dest_len = dest.len() as _;

    let mut strm: bz_stream = bz_stream::zeroed();

    let mut ret = unsafe { BZ2_bzDecompressInit(&mut strm, 0, 0) };

    if ret != 0 {
        return Err(ret);
    }

    strm.next_out = dest.as_mut_ptr().cast::<core::ffi::c_char>();
    strm.avail_out = dest_len;

    for chunk in source.chunks(chunk_size) {
        strm.next_in = chunk.as_ptr() as *mut core::ffi::c_char;
        strm.avail_in = chunk.len() as _;

        ret = unsafe { BZ2_bzDecompress(&mut strm) };

        match ret {
            0 => {
                continue;
            }
            3 => {
                unsafe { BZ2_bzDecompressEnd(&mut strm) };
                return Err(-8);
            }
            4 => {
                dest_len = dest_len.wrapping_sub(strm.avail_out);
                unsafe { BZ2_bzDecompressEnd(&mut strm) };
                return Ok(&mut dest[..dest_len as usize]);
            }
            _ => {
                unsafe { BZ2_bzDecompressEnd(&mut strm) };
                return Err(ret);
            }
        }
    }

    Ok(&mut dest[..dest_len as usize])
}

#[test]
fn decompress_chunked_input() {
    let mut dest_chunked = vec![0; 1 << 18];
    let chunked = decompress_rs_chunked_input(&mut dest_chunked, SAMPLE1_BZ2, 1).unwrap();

    if !cfg!(miri) {
        let mut dest = vec![0; 1 << 18];
        let mut dest_len = dest.len() as _;
        let err = unsafe {
            decompress_c(
                dest.as_mut_ptr(),
                &mut dest_len,
                SAMPLE1_BZ2.as_ptr(),
                SAMPLE1_BZ2.len() as _,
            )
        };
        assert_eq!(err, 0);
        dest.truncate(dest_len as usize);

        assert_eq!(chunked.len(), dest.len());
        assert_eq!(chunked, dest);
    }
}

fn compress_rs_chunked_input<'a>(
    dest: &'a mut [u8],
    source: &[u8],
    chunk_size: usize,
) -> Result<&'a mut [u8], i32> {
    use libbz2_rs_sys::*;

    let mut dest_len = dest.len() as _;

    let mut strm: bz_stream = bz_stream::zeroed();

    let verbosity = 0;
    let block_size_100k = 9;
    let work_factor = 30;

    let mut ret = unsafe { BZ2_bzCompressInit(&mut strm, block_size_100k, verbosity, work_factor) };

    if ret != 0 {
        return Err(ret);
    }

    strm.next_out = dest.as_mut_ptr().cast::<core::ffi::c_char>();
    strm.avail_out = dest_len;

    for chunk in source.chunks(chunk_size) {
        strm.next_in = chunk.as_ptr() as *mut core::ffi::c_char;
        strm.avail_in = chunk.len() as _;

        ret = unsafe { BZ2_bzCompress(&mut strm, 0) };

        match ret {
            0 => {
                continue;
            }
            1 => {
                continue;
            }
            3 => {
                unsafe { BZ2_bzCompressEnd(&mut strm) };
                return Err(-8);
            }
            4 => {
                dest_len = dest_len.wrapping_sub(strm.avail_out);
                unsafe { BZ2_bzCompressEnd(&mut strm) };
                return Ok(&mut dest[..dest_len as usize]);
            }
            _ => {
                unsafe { BZ2_bzCompressEnd(&mut strm) };
                return Err(ret);
            }
        }
    }

    ret = unsafe { BZ2_bzCompress(&mut strm, 2) };
    assert_eq!(ret, 4);
    dest_len = dest_len.wrapping_sub(strm.avail_out);

    unsafe { BZ2_bzCompressEnd(&mut strm) };

    Ok(&mut dest[..dest_len as usize])
}

#[test]
fn compress_chunked_input() {
    let mut dest_chunked = vec![0; 1 << 18];
    let chunked = compress_rs_chunked_input(&mut dest_chunked, SAMPLE1_REF, 256).unwrap();

    if !cfg!(miri) {
        let (err, dest) = unsafe { compress_c(SAMPLE1_REF.as_ptr(), SAMPLE1_REF.len() as _, 9) };
        assert_eq!(err, 0);

        assert_eq!(chunked.len(), dest.len());
        assert_eq!(chunked, dest);
    }
}

fn decompress_rs_chunked_output<'a>(
    dest: &'a mut [u8],
    source: &[u8],
) -> Result<&'a mut [u8], i32> {
    use libbz2_rs_sys::*;

    let mut dest_len = dest.len() as core::ffi::c_uint;

    let mut strm: bz_stream = bz_stream::zeroed();

    let mut ret = unsafe { BZ2_bzDecompressInit(&mut strm, 0, 0) };

    if ret != 0 {
        return Err(ret);
    }

    strm.next_in = source.as_ptr() as *mut core::ffi::c_char;
    strm.avail_in = source.len() as _;

    for chunk in dest.chunks_mut(256) {
        strm.next_out = chunk.as_mut_ptr().cast::<core::ffi::c_char>();
        strm.avail_out = chunk.len() as _;

        ret = unsafe { BZ2_bzDecompress(&mut strm) };

        match ret {
            0 => {
                continue;
            }
            3 => {
                unsafe { BZ2_bzDecompressEnd(&mut strm) };
                return Err(-8);
            }
            4 => {
                dest_len = dest_len.wrapping_sub(strm.avail_out);
                unsafe { BZ2_bzDecompressEnd(&mut strm) };
                return Ok(&mut dest[..dest_len as usize]);
            }
            _ => {
                unsafe { BZ2_bzDecompressEnd(&mut strm) };
                return Err(ret);
            }
        }
    }

    unsafe { BZ2_bzCompressEnd(&mut strm) };

    Ok(&mut dest[..dest_len as usize])
}

#[test]
fn decompress_chunked_output() {
    let mut dest = vec![0; 1 << 18];
    let mut dest_len = dest.len() as _;
    let err = unsafe {
        decompress_c(
            dest.as_mut_ptr(),
            &mut dest_len,
            SAMPLE1_BZ2.as_ptr(),
            SAMPLE1_BZ2.len() as _,
        )
    };
    assert_eq!(err, 0);
    dest.truncate(dest_len as usize);

    let mut dest_chunked = vec![0; 1 << 18];
    let chunked = decompress_rs_chunked_input(&mut dest_chunked, SAMPLE1_BZ2, 1).unwrap();

    assert_eq!(chunked.len(), dest.len());
    assert_eq!(chunked, dest);
}

fn compress_rs_chunked_output<'a>(dest: &'a mut [u8], source: &[u8]) -> Result<&'a mut [u8], i32> {
    use libbz2_rs_sys::*;

    let mut dest_len = dest.len() as core::ffi::c_uint;

    let mut strm: bz_stream = bz_stream::zeroed();

    let verbosity = 0;
    let block_size_100k = 9;
    let work_factor = 30;

    let mut ret = unsafe { BZ2_bzCompressInit(&mut strm, block_size_100k, verbosity, work_factor) };

    if ret != 0 {
        return Err(ret);
    }

    strm.next_in = source.as_ptr() as *mut core::ffi::c_char;
    strm.avail_in = source.len() as _;

    for chunk in dest.chunks_mut(256) {
        strm.next_out = chunk.as_mut_ptr().cast::<core::ffi::c_char>();
        strm.avail_out = chunk.len() as _;

        ret = unsafe { BZ2_bzCompress(&mut strm, 0) };

        match dbg!(ret) {
            0 => {
                continue;
            }
            1 => {
                continue;
            }
            3 => {
                unsafe { BZ2_bzCompressEnd(&mut strm) };
                return Err(-8);
            }
            4 => {
                dest_len = dest_len.wrapping_sub(strm.avail_out);
                unsafe { BZ2_bzCompressEnd(&mut strm) };
                return Ok(&mut dest[..dest_len as usize]);
            }
            _ => {
                unsafe { BZ2_bzCompressEnd(&mut strm) };
                return Err(ret);
            }
        }
    }

    ret = unsafe { BZ2_bzCompress(&mut strm, 2) };
    assert_eq!(ret, 4);
    dest_len = dest_len.wrapping_sub(strm.avail_out);

    Ok(&mut dest[..dest_len as usize])
}

#[test]
fn compress_chunked_output() {
    let mut dest_chunked = vec![0; 1 << 18];
    let chunked = compress_rs_chunked_input(&mut dest_chunked, SAMPLE1_REF, 256).unwrap();

    if !cfg!(miri) {
        let (err, dest) = unsafe { compress_c(SAMPLE1_REF.as_ptr(), SAMPLE1_REF.len() as _, 9) };
        assert_eq!(err, 0);

        assert_eq!(chunked.len(), dest.len());
        assert_eq!(chunked, dest);
    }
}

#[test]
fn fuzzer_short() {
    const INPUT: &[u8] = &[0, 0, 67, 0, 67, 0, 0, 5, 0, 0];

    let (err, input) = unsafe { compress_c(INPUT.as_ptr(), INPUT.len() as u32, 1) };
    assert_eq!(err, 0);

    let mut dest_chunked = vec![0; 1 << 18];
    let _ = decompress_rs_chunked_input(&mut dest_chunked, &input, 6).unwrap();
}
