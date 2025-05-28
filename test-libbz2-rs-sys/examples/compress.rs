use test_libbz2_rs_sys::{compress_c_with_capacity, compress_rs_with_capacity};

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
        other => panic!("invalid option '{other}', expected one of 'c' or 'rs'"),
    }
}
