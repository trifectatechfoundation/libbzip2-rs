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

    // differential testing: ensure both implementations succeed
    assert_eq!(error, error_c);
    assert_eq!(error, BZ_OK);

    // Cross-compatibility testing:
    // Ensure data compressed by Rust can be decompressed by C to the exact input
    let (error_c_decomp, decomp_from_rs_via_c) = unsafe {
        test_libbz2_rs_sys::decompress_c_with_capacity(
            1 << 10,
            deflated.as_ptr(),
            deflated.len() as _,
        )
    };
    assert_eq!(error_c_decomp, BZ_OK);
    assert_eq!(decomp_from_rs_via_c, fuzzed_data);

    // Ensure data compressed by C can be decompressed by Rust to the exact input
    let (error_rs_decomp, decomp_from_c_via_rs) = unsafe {
        test_libbz2_rs_sys::decompress_rs_with_capacity(
            1 << 10,
            deflated_c.as_ptr(),
            deflated_c.len() as _,
        )
    };
    assert_eq!(error_rs_decomp, BZ_OK);
    assert_eq!(decomp_from_c_via_rs, fuzzed_data);

    // Round-trip testing:
    // Ensure data compressed by Rust can also be decompressed by Rust to the exact input
    let (error_rs_rt, decomp_rs_rt) = unsafe {
        test_libbz2_rs_sys::decompress_rs_with_capacity(
            1 << 10,
            deflated.as_ptr(),
            deflated.len() as _,
        )
    };
    assert_eq!(error_rs_rt, BZ_OK);
    assert_eq!(decomp_rs_rt, fuzzed_data);
});
