#![no_main]
use libbz2_rs_sys::bz_stream;
use libbz2_rs_sys::BZ2_bzDecompress;
use libbz2_rs_sys::BZ2_bzDecompressEnd;
use libbz2_rs_sys::BZ2_bzDecompressInit;
use libbz2_rs_sys::{
    BZ_CONFIG_ERROR, BZ_DATA_ERROR, BZ_DATA_ERROR_MAGIC, BZ_FINISH, BZ_FINISH_OK, BZ_FLUSH_OK,
    BZ_IO_ERROR, BZ_MEM_ERROR, BZ_OK, BZ_OUTBUFF_FULL, BZ_PARAM_ERROR, BZ_RUN_OK,
    BZ_SEQUENCE_ERROR, BZ_STREAM_END, BZ_UNEXPECTED_EOF,
};

use libfuzzer_sys::fuzz_target;

/// compress the data with the stock C bzip2
fn compress_c(data: &[u8], compression_level: u8, work_factor: u8) -> Vec<u8> {
    // output buffer for compression, will get resized later if needed
    let mut output = Vec::<u8>::with_capacity(1024);

    let mut stream = libbz2_rs_sys::bz_stream {
        next_in: data.as_ptr() as *mut _,
        avail_in: data.len() as _,
        total_in_lo32: 0,
        total_in_hi32: 0,
        avail_out: output.capacity() as _,
        next_out: output.as_mut_ptr() as *mut _,
        total_out_lo32: 0,
        total_out_hi32: 0,
        state: std::ptr::null_mut(),
        bzalloc: None,
        bzfree: None,
        opaque: std::ptr::null_mut(),
    };

    unsafe {
        let err = libbz2_rs_sys::BZ2_bzCompressInit(
            &mut stream,
            compression_level.into(),
            0,
            work_factor.into(),
        );
        // init should always succeed
        assert_eq!(err, BZ_OK);
    };

    let error = loop {
        match unsafe { libbz2_rs_sys::BZ2_bzCompress(&mut stream, BZ_FINISH) } {
            BZ_FINISH_OK => {
                let used = output.capacity() - stream.avail_out as usize;

                // Safety: we've written this many (initialized!) bytes to the output.
                unsafe { output.set_len(used) };

                // The output buffer is full, resize it
                let add_space: u32 = Ord::max(1024, output.capacity().try_into().unwrap());
                output.reserve(add_space as usize);

                // If resize() reallocates, it may have moved in memory
                stream.next_out = output.as_mut_ptr().cast::<i8>().wrapping_add(used);
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

    // compression should always succeed
    assert_eq!(error, BZ_OK);

    // truncate the output buffer down to the actual number of compressed bytes
    let total = u64::from(stream.total_out_hi32) << 32 | u64::from(stream.total_out_lo32);
    unsafe { output.set_len(usize::try_from(total).unwrap()) };

    // Just check that this byte is in fact initialized.
    std::hint::black_box(output.last() == Some(&0));

    unsafe {
        // cleanup, should always succeed
        let err = libbz2_rs_sys::BZ2_bzCompressEnd(&mut stream);
        assert_eq!(err, BZ_OK);
    }

    output
}

fuzz_target!(|input: (&[u8], usize, u8, u8)| {
    let (fuzzer_data, chunk_size, compression_decider, work_factor_decider) = input;

    // let the fuzzer pick a value from 1 to 9 (inclusive)
    // use modulo to ensure this always maps to a valid number
    let compression_level: u8 = (compression_decider % 9) + 1;

    // valid values 0 to 250 (inclusive)
    // use modulo to ensure this always maps to a valid number
    let work_factor = work_factor_decider % 251;

    if chunk_size == 0 {
        // we can't iterate over chunks of size 0 byte, exit early
        return;
    }

    let compressed_data = compress_c(fuzzer_data, compression_level, work_factor);

    let mut stream = bz_stream::zeroed();

    unsafe {
        let err = BZ2_bzDecompressInit(&mut stream, 0, 0);
        assert_eq!(err, BZ_OK);
    };

    // output buffer for decompression, will get resized later if needed
    let mut output = vec![0u8; 1 << 10];
    stream.next_out = output.as_mut_ptr() as *mut _;
    stream.avail_out = output.len() as _;

    // iterate over chunks of the compressed data
    'decompression: for chunk in compressed_data.as_slice().chunks(chunk_size) {
        // designate the current chunk as input
        stream.next_in = chunk.as_ptr() as *mut _;
        stream.avail_in = chunk.len() as _;

        loop {
            // perform one round of decompression
            let err = unsafe { BZ2_bzDecompress(&mut stream) };
            match err {
                BZ_OK => {
                    // the decompression mechanism still has data in the input buffer,
                    // but no more space in the output buffer
                    if stream.avail_in > 0 && stream.avail_out == 0 {
                        let used = output.len() - stream.avail_out as usize;
                        // The dest buffer is full, increase its size
                        let add_space: u32 = Ord::max(1024, output.len().try_into().unwrap());
                        output.resize(output.len() + add_space as usize, 0);

                        // If resize() reallocates, it may have moved in memory
                        stream.next_out = output.as_mut_ptr().cast::<i8>().wrapping_add(used);
                        stream.avail_out += add_space;
                        continue;
                    } else {
                        // the decompression of this chunk step was successful, move on to the next
                        break;
                    }
                }
                BZ_STREAM_END => {
                    // the decompression has completed, exit loops
                    break 'decompression;
                }
                BZ_RUN_OK => panic!("BZ_RUN_OK"),
                BZ_FLUSH_OK => panic!("BZ_FLUSH_OK"),
                BZ_FINISH_OK => panic!("BZ_FINISH_OK"),
                BZ_SEQUENCE_ERROR => panic!("BZ_SEQUENCE_ERROR"),
                BZ_PARAM_ERROR => panic!("BZ_PARAM_ERROR"),
                BZ_MEM_ERROR => panic!("BZ_MEM_ERROR"),
                BZ_DATA_ERROR => {
                    panic!("BZ_DATA_ERROR")
                }
                BZ_DATA_ERROR_MAGIC => panic!("BZ_DATA_ERROR_MAGIC"),
                BZ_IO_ERROR => panic!("BZ_IO_ERROR"),
                BZ_UNEXPECTED_EOF => panic!("BZ_UNEXPECTED_EOF"),
                BZ_OUTBUFF_FULL => panic!("BZ_OUTBUFF_FULL"),
                BZ_CONFIG_ERROR => panic!("BZ_CONFIG_ERROR"),
                _ => panic!("{err}"),
            }
        }
    }

    // truncate the output buffer down to the actual number of decompressed bytes
    output.truncate(
        ((u64::from(stream.total_out_hi32) << 32) + u64::from(stream.total_out_lo32))
            .try_into()
            .unwrap(),
    );

    unsafe {
        // cleanup, should always succeed
        let err = BZ2_bzDecompressEnd(&mut stream);
        assert_eq!(err, BZ_OK);
    }

    // round-trip check
    // compressing and then decompressing should lead back to the input data
    assert_eq!(output, fuzzer_data);
});
