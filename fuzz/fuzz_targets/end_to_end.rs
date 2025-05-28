#![no_main]
use libbz2_rs_sys::BZ_OK;
use libfuzzer_sys::fuzz_target;

fn decompress_help(input: &[u8]) -> Vec<u8> {
    let source = input.as_ptr();
    let source_len = input.len() as _;

    let (err, dest_vec) =
        unsafe { test_libbz2_rs_sys::decompress_rs_with_capacity(1 << 16, source, source_len) };

    if err != BZ_OK {
        panic!("error {:?}", err);
    }

    dest_vec
}

fuzz_target!(|data: Vec<u8>| {
    let (error, deflated) = unsafe {
        test_libbz2_rs_sys::compress_c_with_capacity(4096, data.as_ptr().cast(), data.len() as _, 9)
    };

    assert_eq!(error, BZ_OK);

    let output = decompress_help(&deflated);

    if output != data {
        let path = std::env::temp_dir().join("deflate.txt");
        std::fs::write(&path, &data).unwrap();
        eprintln!("saved input file to {path:?}");
    }

    assert_eq!(output, data);
});
