#![no_main]
use libbz2_rs_sys::{BZ_FINISH, BZ_FINISH_OK, BZ_OK, BZ_STREAM_END};
use libfuzzer_sys::fuzz_target;

fn compress_c(data: &[u8]) -> Vec<u8> {
    // First, decompress the data with the stock C bzip2.
    let mut output = vec![0u8; 1024];

    let mut stream = bzip2_sys::bz_stream {
        next_in: data.as_ptr() as *mut _,
        avail_in: data.len() as _,
        total_in_lo32: 0,
        total_in_hi32: 0,
        next_out: output.as_mut_ptr() as *mut _,
        avail_out: output.len() as _,
        total_out_lo32: 0,
        total_out_hi32: 0,
        state: std::ptr::null_mut(),
        bzalloc: None,
        bzfree: None,
        opaque: std::ptr::null_mut(),
    };

    unsafe {
        let err = bzip2_sys::BZ2_bzCompressInit(&mut stream, 9, 0, 250);
        assert_eq!(err, BZ_OK);
    };

    let error = loop {
        match unsafe { bzip2_sys::BZ2_bzCompress(&mut stream, BZ_FINISH) } {
            BZ_FINISH_OK => {
                let used = output.len() - stream.avail_out as usize;
                // The output buffer is full.
                let add_space: u32 = Ord::max(1024, output.len().try_into().unwrap());
                output.resize(output.len() + add_space as usize, 0);

                // If resize() reallocates, it may have moved in memory.
                stream.next_out = output.as_mut_ptr().cast::<i8>().wrapping_add(used as usize);
                stream.avail_out += add_space;

                continue;
            }
            BZ_STREAM_END => {
                break BZ_OK;
            }
            ret => {
                break ret;
            }
        }
    };

    assert_eq!(error, BZ_OK);

    output.truncate(
        ((u64::from(stream.total_out_hi32) << 32) + u64::from(stream.total_out_lo32))
            .try_into()
            .unwrap(),
    );

    unsafe {
        let err = bzip2_sys::BZ2_bzCompressEnd(&mut stream);
        assert_eq!(err, BZ_OK);
    }

    output
}

fuzz_target!(|input: (String, usize)| {
    use libbz2_rs_sys::*;

    let (data, chunk_size) = input;

    if chunk_size == 0 {
        return;
    }

    let deflated = compress_c(data.as_bytes());

    let mut stream = bz_stream::zeroed();

    unsafe {
        let err = BZ2_bzDecompressInit(&mut stream, 0, 0);
        assert_eq!(err, BZ_OK);
    };

    let mut output = vec![0u8; 1 << 15];
    stream.next_out = output.as_mut_ptr() as *mut _;
    stream.avail_out = output.len() as _;

    for chunk in deflated.as_slice().chunks(chunk_size) {
        stream.next_in = chunk.as_ptr() as *mut _;
        stream.avail_in = chunk.len() as _;

        let err = unsafe { BZ2_bzDecompress(&mut stream) };
        match err {
            BZ_OK => continue,
            BZ_RUN_OK => panic!("BZ_RUN_OK"),
            BZ_FLUSH_OK => panic!("BZ_FLUSH_OK"),
            BZ_FINISH_OK => panic!("BZ_FINISH_OK"),
            BZ_STREAM_END => continue,
            BZ_SEQUENCE_ERROR => panic!("BZ_SEQUENCE_ERROR"),
            BZ_PARAM_ERROR => panic!("BZ_PARAM_ERROR"),
            BZ_MEM_ERROR => panic!("BZ_MEM_ERROR"),
            BZ_DATA_ERROR => panic!("BZ_DATA_ERROR"),
            BZ_DATA_ERROR_MAGIC => panic!("BZ_DATA_ERROR_MAGIC"),
            BZ_IO_ERROR => panic!("BZ_IO_ERROR"),
            BZ_UNEXPECTED_EOF => panic!("BZ_UNEXPECTED_EOF"),
            BZ_OUTBUFF_FULL => panic!("BZ_OUTBUFF_FULL"),
            BZ_CONFIG_ERROR => panic!("BZ_CONFIG_ERROR"),
            _ => panic!("{err}"),
        }
    }

    output.truncate(
        ((u64::from(stream.total_out_hi32) << 32) + u64::from(stream.total_out_lo32))
            .try_into()
            .unwrap(),
    );
    let output = String::from_utf8(output).unwrap();

    unsafe {
        let err = BZ2_bzDecompressEnd(&mut stream);
        assert_eq!(err, BZ_OK);
    }

    if output != data {
        let path = std::env::temp_dir().join("deflate.txt");
        std::fs::write(&path, &data).unwrap();
        eprintln!("saved input file to {path:?}");
    }

    assert_eq!(output, data);
});
