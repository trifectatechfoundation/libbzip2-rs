#![no_main]
use libbz2_rs_sys::BZ_OK;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: String| {
    let (error, deflated) = unsafe {
        test_libbz2_rs_sys::compress_rs_with_capacity(
            4096,
            data.as_ptr().cast(),
            data.len() as _,
            9,
        )
    };

    assert_eq!(error, BZ_OK);

    let (error, output) = unsafe {
        test_libbz2_rs_sys::decompress_rs_with_capacity(
            1 << 10,
            deflated.as_ptr(),
            deflated.len() as _,
        )
    };
    assert_eq!(error, BZ_OK);

    if output != data.as_bytes() {
        let path = std::env::temp_dir().join("compressed.txt");
        std::fs::write(&path, &data).unwrap();
        eprintln!("saved input file to {path:?}");
    }

    assert_eq!(output, data.as_bytes());
});
