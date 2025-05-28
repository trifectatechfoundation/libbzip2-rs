#![no_main]
use libbz2_rs_sys::BZ_OK;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|source: Vec<u8>| {
    let (err_c, dest_c) = unsafe {
        test_libbz2_rs_sys::decompress_c_with_capacity(1 << 16, source.as_ptr(), source.len() as _)
    };

    let (err_rs, dest_rs) = unsafe {
        test_libbz2_rs_sys::decompress_rs_with_capacity(1 << 16, source.as_ptr(), source.len() as _)
    };

    assert_eq!(err_c, err_rs);

    if err_c == BZ_OK {
        assert_eq!(dest_c, dest_rs);
    }
});
