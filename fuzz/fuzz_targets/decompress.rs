#![no_main]
use libbz2_rs_sys::BZ_OK;
use libfuzzer_sys::fuzz_target;

// this fuzz target is designed to work directly with unmodified bzip2 files
fuzz_target!(|fuzz_data: &[u8]| {
    let (err_c, decompressed_c) = unsafe {
        test_libbz2_rs_sys::decompress_c_with_capacity(
            1 << 12,
            fuzz_data.as_ptr(),
            fuzz_data.len() as _,
        )
    };

    let (err_rs, decompressed_rs) = unsafe {
        test_libbz2_rs_sys::decompress_rs_with_capacity(
            1 << 12,
            fuzz_data.as_ptr(),
            fuzz_data.len() as _,
        )
    };

    #[cfg(feature = "disable-checksum")]
    compile_error!(
        "Problematic feature enabled! Skipping CRC checksums will cause false positives here."
    );

    // result codes between the two implementations should be identical
    // previously found https://github.com/trifectatechfoundation/libbzip2-rs/pull/110
    assert_eq!(err_c, err_rs);

    // if the decompression is successful, the data results should be the same
    if err_c == BZ_OK {
        assert_eq!(decompressed_c, decompressed_rs);
    }
});
