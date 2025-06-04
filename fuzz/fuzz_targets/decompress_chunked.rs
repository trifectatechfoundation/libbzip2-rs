#![no_main]

use libbz2_rs_sys::{bz_stream, BZ2_bzDecompress, BZ2_bzDecompressEnd, BZ2_bzDecompressInit};
use libbz2_rs_sys::{
    BZ_DATA_ERROR, BZ_DATA_ERROR_MAGIC, BZ_FINISH_OK, BZ_FLUSH_OK, BZ_OK, BZ_OUTBUFF_FULL,
    BZ_RUN_OK, BZ_STREAM_END,
};
use libfuzzer_sys::{fuzz_target, Corpus};

// this fuzz target is designed to work directly with unmodified bzip2 files
fuzz_target!(|fuzz_data: &[u8]| -> Corpus {
    // Limitation: we can't explicitly add extra fuzzer input data to influence the computation
    // Workaround: pick either small or fast based on a byte of input data
    let small = fuzz_data
        .get(fuzz_data.len() / 2)
        .is_some_and(|v| v % 2 == 0);

    // Small enough to hit interesting cases, but large enough to hit the fast path
    let chunk_size = 16;

    // Initialize decompression context, this should succeed
    let mut stream: bz_stream = bz_stream::zeroed();
    let ret = unsafe { BZ2_bzDecompressInit(&mut stream, 0, small as _) };
    assert_eq!(ret, libbz2_rs_sys::BZ_OK);

    // libFuzzer has an optional mechanism to explicitly reject fuzz inputs
    // This directive forces the fuzzer to forget the observed coverage for the current input,
    // and does not allow adding it to the corpus collection
    //
    // See https://llvm.org/docs/LibFuzzer.html#rejecting-unwanted-inputs
    //
    // This is a heavy-handed approach and reduces fuzzer coverage visibility into
    // the rejected code paths, but may be useful for time-constrained runs
    //
    // Expected effects:
    // 1. reduce some runtime overhead on rejected inputs by skipping post-processing steps
    // 2. increases ratio of "valid" inputs in working corpus
    //
    // The expectation is that this makes it more likely to create valid inputs by mutation,
    // at least on short runs with a limited amount of executions that start on a pre-seeded corpus
    let invalid_input = if cfg!(feature = "reject-invalid-in-corpus") {
        // instruct libFuzzer to reject and ignore this input
        Corpus::Reject
    } else {
        // normal neutral behavior
        Corpus::Keep
    };

    // initialize output buffer, resizing will happen later if needed
    // using the input length is just a quick heuristic and not otherwise meaningful or necessary
    let mut output = vec![0u8; fuzz_data.len()];
    let output_len = output.len() as _;

    // set output buffer in decompression context
    stream.next_out = output.as_mut_ptr().cast::<core::ffi::c_char>();
    stream.avail_out = output_len;

    // iterate over chunks in the compressed data
    'decompression: for chunk in fuzz_data.chunks(chunk_size) {
        // set new chunk as input
        stream.next_in = chunk.as_ptr() as *mut core::ffi::c_char;
        stream.avail_in = chunk.len() as _;

        // process this chunk
        loop {
            // perform decompression
            match unsafe { BZ2_bzDecompress(&mut stream) } {
                BZ_STREAM_END => {
                    // stream complete, stop processing chunks
                    break 'decompression;
                }
                BZ_OK => {
                    // there is still input from this chunk left to process but no more output buffer
                    // this means we have to increase the output buffer and retry the decompress
                    if stream.avail_in > 0 && stream.avail_out == 0 {
                        let used = output.len() - stream.avail_out as usize;
                        // The dest buffer is full, resize it
                        let add_space: u32 = Ord::max(4096, output.len().try_into().unwrap());
                        output.resize(output.len() + add_space as usize, 0);

                        // If resize() reallocates, it may have moved in memory
                        stream.next_out = output.as_mut_ptr().cast::<i8>().wrapping_add(used);
                        stream.avail_out += add_space;

                        continue;
                    } else if stream.avail_in == 0 {
                        // stop processing this chunk
                        break;
                    }

                    continue;
                }
                BZ_DATA_ERROR | BZ_DATA_ERROR_MAGIC => {
                    // valid reasons for decompression errors if the input is invalid

                    // clean up state
                    unsafe { BZ2_bzDecompressEnd(&mut stream) };

                    // stop processing
                    return invalid_input;
                }
                BZ_FLUSH_OK => panic!("BZ_FLUSH_OK"),
                BZ_RUN_OK => panic!("BZ_RUN_OK"),
                BZ_FINISH_OK => panic!("BZ_FINISH_OK"),
                BZ_OUTBUFF_FULL => panic!("BZ_OUTBUFF_FULL"),
                err => panic!("{err}"),
            }
        }
    }

    unsafe {
        // clean up state, should always succeed
        let err = BZ2_bzDecompressEnd(&mut stream);
        if err != BZ_OK {
            return invalid_input;
        }
    }

    Corpus::Keep
});
