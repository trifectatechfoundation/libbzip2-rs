use std::env;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Useful to test with the C binary
fn bzip2recover_binary() -> &'static str {
    env!("CARGO_BIN_EXE_bzip2recover")
}

pub fn runner() -> Option<String> {
    std::env::var("RUNNER").ok().or_else(|| {
        if cfg!(target_arch = "s390x") {
            std::env::var("CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_RUNNER").ok()
        } else {
            None
        }
    })
}

fn run_bzip2recover(path: Option<&Path>) -> std::process::Output {
    let mut cmd = match crate::runner() {
        Some(runner) if !runner.is_empty() => {
            let mut runner_args = runner.split(' ');
            let mut cmd = Command::new(runner_args.next().unwrap());
            cmd.args(runner_args);
            cmd.arg(bzip2recover_binary());

            cmd
        }
        _ => Command::new(bzip2recover_binary()),
    };

    if let Some(path) = path {
        cmd.arg(path.as_os_str()).stdout(Stdio::piped());
    }

    match cmd.output() {
        Ok(output) => output,
        Err(err) => panic!("Running {cmd:?} failed with {err:?}"),
    }
}

fn checksum(path: &Path) -> u32 {
    crc32fast::hash(&std::fs::read(path).unwrap())
}

#[test]
fn basic_valid_file() {
    let tmp = tempfile::tempdir().unwrap();
    let tmp_path_str = tmp.path().display().to_string();

    let file_path = tmp.path().join("sample1.bz2");
    let mut file = File::create(&file_path).unwrap();

    file.write_all(include_bytes!("input/quick/sample2.bz2"))
        .unwrap();

    drop(file);

    let output = run_bzip2recover(Some(&file_path));

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());

    assert_eq!(
        String::from_utf8_lossy(&output.stderr)
            .replace(&tmp_path_str, "$TEMPDIR")
            .replace(bzip2recover_binary(), "bzip2recover")
            .replace("\\", "/"),
        concat!(
            "bzip2recover 1.0.6: extracts blocks from damaged .bz2 files.\n",
            "bzip2recover: searching for block boundaries ...\n",
            "   block 1 runs from 80 to 544887\n",
            "   block 2 runs from 544936 to 589771\n",
            "bzip2recover: splitting into blocks\n",
            "   writing block 1 to `$TEMPDIR/rec00001sample1.bz2' ...\n",
            "   writing block 2 to `$TEMPDIR/rec00002sample1.bz2' ...\n",
            "bzip2recover: finished\n"
        )
    );

    assert_eq!(
        checksum(&tmp.path().join("rec00001sample1.bz2")),
        2309536424
    );
    assert_eq!(
        checksum(&tmp.path().join("rec00002sample1.bz2")),
        1823861694
    );
}

#[test]
fn basic_invalid_file() {
    let tmp = tempfile::tempdir().unwrap();
    let tmp_path_str = tmp.path().display().to_string();

    let file_path = tmp.path().join("sample1.bz2");
    let mut file = File::create(&file_path).unwrap();

    // create an input with some data missing
    let input = include_bytes!("input/quick/sample2.bz2");
    let input = &input[..input.len() - 100];

    file.write_all(input).unwrap();

    drop(file);

    let output = run_bzip2recover(Some(&file_path));

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());

    assert_eq!(
        String::from_utf8_lossy(&output.stderr)
            .replace(&tmp_path_str, "$TEMPDIR")
            .replace(bzip2recover_binary(), "bzip2recover")
            .replace("\\", "/"),
        concat!(
            "bzip2recover 1.0.6: extracts blocks from damaged .bz2 files.\n",
            "bzip2recover: searching for block boundaries ...\n",
            "   block 1 runs from 80 to 544887\n",
            "   block 2 runs from 544936 to 589056 (incomplete)\n",
            "bzip2recover: splitting into blocks\n",
            "   writing block 1 to `$TEMPDIR/rec00001sample1.bz2' ...\n",
            "bzip2recover: finished\n",
        )
    );

    assert_eq!(
        checksum(&tmp.path().join("rec00001sample1.bz2")),
        2309536424
    );

    assert!(!tmp.path().join("rec00003sample1.bz2").exists());
}

#[test]
fn no_input_file() {
    let output = run_bzip2recover(None);

    assert!(
        !output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());

    assert_eq!(
        String::from_utf8_lossy(&output.stderr).replace(bzip2recover_binary(), "bzip2recover"),
        concat!(
            "bzip2recover 1.0.6: extracts blocks from damaged .bz2 files.\n",
            "bzip2recover: usage is `bzip2recover damaged_file_name'.\n",
            "\trestrictions on size of recovered file: None\n"
        )
    );
}

#[test]
fn nonexistent_input_file() {
    let output = run_bzip2recover(Some(Path::new("does_not_exist.txt")));

    assert!(
        !output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());

    assert_eq!(
        String::from_utf8_lossy(&output.stderr).replace(bzip2recover_binary(), "bzip2recover"),
        concat!(
            "bzip2recover 1.0.6: extracts blocks from damaged .bz2 files.\n",
            "bzip2recover: can't read `does_not_exist.txt'\n",
        )
    );
}

#[test]
fn random_input_data() {
    let tmp = tempfile::tempdir().unwrap();
    let tmp_path_str = tmp.path().display().to_string();

    let file_path = tmp.path().join("sample1.bz2");
    let mut file = File::create(&file_path).unwrap();

    file.write_all(include_bytes!("input/quick/sample1.ref"))
        .unwrap();

    drop(file);

    let output = run_bzip2recover(Some(&file_path));

    assert!(
        !output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());

    assert_eq!(
        String::from_utf8_lossy(&output.stderr)
            .replace(&tmp_path_str, "$TEMPDIR")
            .replace(bzip2recover_binary(), "bzip2recover"),
        concat!(
            "bzip2recover 1.0.6: extracts blocks from damaged .bz2 files.\n",
            "bzip2recover: searching for block boundaries ...\n",
            "bzip2recover: sorry, I couldn't find any block boundaries.\n"
        )
    );
}

#[test]
fn does_not_overwrite_recovered_files() {
    let tmp = tempfile::tempdir().unwrap();
    let tmp_path_str = tmp.path().display().to_string();

    let file_path = tmp.path().join("sample1.bz2");
    let mut file = File::create(&file_path).unwrap();

    file.write_all(include_bytes!("input/quick/sample2.bz2"))
        .unwrap();

    drop(file);

    let output = run_bzip2recover(Some(&file_path));

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());

    assert_eq!(
        String::from_utf8_lossy(&output.stderr)
            .replace(&tmp_path_str, "$TEMPDIR")
            .replace(bzip2recover_binary(), "bzip2recover")
            .replace("\\", "/"),
        concat!(
            "bzip2recover 1.0.6: extracts blocks from damaged .bz2 files.\n",
            "bzip2recover: searching for block boundaries ...\n",
            "   block 1 runs from 80 to 544887\n",
            "   block 2 runs from 544936 to 589771\n",
            "bzip2recover: splitting into blocks\n",
            "   writing block 1 to `$TEMPDIR/rec00001sample1.bz2' ...\n",
            "   writing block 2 to `$TEMPDIR/rec00002sample1.bz2' ...\n",
            "bzip2recover: finished\n"
        )
    );

    // now we run the same command. The output files are only created when they don't already
    // exist.

    let output = run_bzip2recover(Some(&file_path));

    assert!(
        !output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());

    assert_eq!(
        String::from_utf8_lossy(&output.stderr)
            .replace(&tmp_path_str, "$TEMPDIR")
            .replace(bzip2recover_binary(), "bzip2recover")
            .replace("\\", "/"),
        concat!(
            "bzip2recover 1.0.6: extracts blocks from damaged .bz2 files.\n",
            "bzip2recover: searching for block boundaries ...\n",
            "   block 1 runs from 80 to 544887\n",
            "   block 2 runs from 544936 to 589771\n",
            "bzip2recover: splitting into blocks\n",
            "   writing block 1 to `$TEMPDIR/rec00001sample1.bz2' ...\n",
            "bzip2recover: can't write `$TEMPDIR/rec00001sample1.bz2'\n",
        )
    );
}

#[test]
fn very_long_file_name() {
    let file_path = PathBuf::from("NaN".repeat(1000) + " batman!.txt");
    let output = run_bzip2recover(Some(&file_path));

    assert!(
        !output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());

    assert_eq!(
        String::from_utf8_lossy(&output.stderr).replace(bzip2recover_binary(), "bzip2recover"),
        concat!(
            "bzip2recover 1.0.6: extracts blocks from damaged .bz2 files.\n",
            "bzip2recover: supplied filename is suspiciously (>= 3012 chars) long.  Bye!\n",
        )
    );
}
