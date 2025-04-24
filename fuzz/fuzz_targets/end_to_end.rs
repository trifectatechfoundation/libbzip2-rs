#![no_main]
use libbz2_rs_sys::BZ_OK;
use libfuzzer_sys::fuzz_target;

fn decompress_help(input: &[u8]) -> Vec<u8> {
    let mut dest_vec = vec![0u8; 1 << 16];

    let mut dest_len = dest_vec.len() as _;
    let dest = dest_vec.as_mut_ptr();

    let source = input.as_ptr();
    let source_len = input.len() as _;

    let err = unsafe { test_libbz2_rs_sys::decompress_rs(dest, &mut dest_len, source, source_len) };

    if err != BZ_OK {
        panic!("error {:?}", err);
    }

    dest_vec.truncate(dest_len as usize);

    dest_vec
}

fuzz_target!(|data: Vec<u8>| {
    let mut length = 8 * 1024;
    let mut deflated = vec![0; length as usize];

    let error = unsafe {
        test_libbz2_rs_sys::compress_c(
            deflated.as_mut_ptr().cast(),
            &mut length,
            data.as_ptr().cast(),
            data.len() as _,
            9,
        )
    };

    assert_eq!(error, BZ_OK);

    deflated.truncate(length as _);

    let output = decompress_help(&deflated);

    if output != data {
        let path = std::env::temp_dir().join("deflate.txt");
        std::fs::write(&path, &data).unwrap();
        eprintln!("saved input file to {path:?}");
    }

    assert_eq!(output, data);
});
