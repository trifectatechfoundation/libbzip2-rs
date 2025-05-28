use test_libbz2_rs_sys::{decompress_c_with_capacity, decompress_rs_with_capacity};

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
        other => panic!("invalid option '{other}', expected one of 'c' or 'rs'"),
    }
}
