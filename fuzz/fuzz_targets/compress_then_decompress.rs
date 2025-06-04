#![no_main]
use libbz2_rs_sys::BZ_OK;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (&[u8], u8)| {
    let (fuzzed_data, compression_decider) = input;

    // let the fuzzer pick a value from 1 to 9 (inclusive)
    // use modulo to ensure this always maps to a valid number
    let compression_level: u8 = (compression_decider % 9) + 1;

    // compress the fuzzer-controlled data via the Rust implementation
    let (error, deflated) = unsafe {
        test_libbz2_rs_sys::compress_rs_with_capacity(
            4096,
            fuzzed_data.as_ptr().cast(),
            fuzzed_data.len() as _,
            compression_level.into(),
        )
    };

    // compress the fuzzer-controlled data via the C implementation
    let (error_c, deflated_c) = unsafe {
        test_libbz2_rs_sys::compress_c_with_capacity(
            4096,
            fuzzed_data.as_ptr().cast(),
            fuzzed_data.len() as _,
            compression_level.into(),
        )
    };

    // differential testing: ensure both implementations behave identically
    assert_eq!(error, error_c);
    assert_eq!(deflated, deflated_c);

    // this compression step should always succeed
    assert_eq!(error, BZ_OK);

    // decompress the previously compressed data again to test round-trip behavior
    let (error, decompressed_output) = unsafe {
        test_libbz2_rs_sys::decompress_rs_with_capacity(
            1 << 10,
            deflated.as_ptr(),
            deflated.len() as _,
        )
    };
    // this decompression of valid compressed data should always succeed
    assert_eq!(error, BZ_OK);

    // after the round trip through compression + decompression, the result data
    // should be identical to the initial data
    assert_eq!(decompressed_output, fuzzed_data);
});
