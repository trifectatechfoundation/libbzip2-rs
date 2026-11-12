use std::ffi::{c_char, CStr};

use test_libbz2_rs_sys::{decompress_c_with_capacity, decompress_rs_with_capacity};

extern "C" {
    // bzip2-sys does not expose this method
    fn BZ2_bzlibVersion() -> *const c_char;
}

fn main() {
    let mut it = std::env::args();

    let _ = it.next().unwrap();

    match it.next().unwrap().as_str() {
        "c" => {
            let path = it.next().unwrap();
            let input = std::fs::read(&path).unwrap();

            let source = input.as_ptr();
            let source_len = input.len() as _;

            let (err, dest_vec) =
                unsafe { decompress_c_with_capacity(1 << 28, source, source_len) };

            if err != 0 {
                panic!("error {err}");
            }

            drop(dest_vec)
        }
        "rs" => {
            let path = it.next().unwrap();
            let input = std::fs::read(&path).unwrap();

            let source = input.as_ptr();
            let source_len = input.len() as _;

            let (err, dest_vec) =
                unsafe { decompress_rs_with_capacity(1 << 28, source, source_len) };

            if err != 0 {
                panic!("error {err}");
            }

            drop(dest_vec)
        }
        "version-rs" => println!(env!("CARGO_PKG_VERSION")),
        "version-c" => println!(
            "{}",
            unsafe { CStr::from_ptr(BZ2_bzlibVersion()) }
                .to_str()
                .unwrap()
        ),
        other => panic!("invalid option '{other}', expected one of 'c' or 'rs'"),
    }
}
