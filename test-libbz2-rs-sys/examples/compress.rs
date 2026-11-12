use std::ffi::{c_char, CStr};

use test_libbz2_rs_sys::{compress_c_with_capacity, compress_rs_with_capacity};

extern "C" {
    // bzip2-sys does not expose this method
    fn BZ2_bzlibVersion() -> *const c_char;
}

fn main() {
    let mut it = std::env::args();

    let _ = it.next().unwrap();

    match it.next().unwrap().as_str() {
        "c" => {
            let level: i32 = it.next().unwrap().parse().unwrap();

            let path = it.next().unwrap();
            let input = std::fs::read(&path).unwrap();

            let source = input.as_ptr();
            let source_len = input.len() as _;

            let (err, dest_vec) =
                unsafe { compress_c_with_capacity(1 << 18, source, source_len, level) };

            if err != 0 {
                panic!("error {err}");
            }

            drop(dest_vec)
        }
        "rs" => {
            let level: i32 = it.next().unwrap().parse().unwrap();

            let path = it.next().unwrap();
            let input = std::fs::read(&path).unwrap();

            let source = input.as_ptr();
            let source_len = input.len() as _;

            let (err, dest_vec) =
                unsafe { compress_rs_with_capacity(1 << 18, source, source_len, level) };

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
