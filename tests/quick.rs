use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Useful to test with the C binary
fn bzip2_binary() -> &'static str {
    env!("CARGO_BIN_EXE_bzip2")
}

#[macro_export]
macro_rules! expect_output_failure {
    ($output:expr, $expected_stderr:expr $(,)?) => {
        assert!(
            !$output.status.success(),
            "status is success (expected failure): {:?} stderr: {:?}",
            $output.status,
            String::from_utf8_lossy(&$output.stderr)
        );

        assert!(
            $output.stdout.is_empty(),
            "stdout: {:?}",
            String::from_utf8_lossy(&$output.stdout)
        );

        assert_eq!(
            String::from_utf8_lossy(&$output.stderr)
                .replace(bzip2_binary(), "bzip2")
                .replace("bzip2.exe", "bzip2")
                .replace("\\", "/")
                .replace("\r\n", "\n"),
            $expected_stderr.replace("\\", "/"),
        );
    };
}

#[macro_export]
macro_rules! expect_failure {
    ($cmd:expr, $expected_stderr:expr $(,)?) => {
        let cmd = $cmd;
        let output = match cmd.output() {
            Ok(output) => output,
            Err(err) => panic!("Running {:?} failed with {err:?}", cmd),
        };

        expect_output_failure!(output, $expected_stderr);
    };
}

#[macro_export]
macro_rules! expect_output_success {
    ($output:expr, $expected_stderr:expr $(,)?) => {
        assert!(
            $output.status.success(),
            "status is failure (expected success) {:?} stderr: {:?}",
            $output.status,
            String::from_utf8_lossy(&$output.stderr)
        );

        assert_eq!(
            String::from_utf8_lossy(&$output.stderr)
                .replace(bzip2_binary(), "bzip2")
                .replace("bzip2.exe", "bzip2")
                .replace("\\", "/")
                .replace("\r\n", "\n"),
            $expected_stderr.replace("\\", "/"),
        );
    };
}

#[macro_export]
macro_rules! expect_success {
    ($cmd:expr, $expected_stderr:expr $(,)?) => {
        let cmd = $cmd;
        let output = match cmd.output() {
            Ok(output) => output,
            Err(err) => panic!("Running {:?} failed with {err:?}", cmd),
        };

        expect_output_success!(output, $expected_stderr);
    };
}

#[cfg(unix)]
fn setup_custom_tty() -> (std::process::Stdio, std::process::Stdio) {
    use std::os::fd::FromRawFd;

    // Open a new PTY master device
    let master_fd = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    if master_fd == -1 {
        panic!("{}", std::io::Error::last_os_error());
    }

    // Grant access to the slave PTY
    if unsafe { libc::grantpt(master_fd) } < 0 {
        panic!("{}", std::io::Error::last_os_error());
    }

    // Unlock the slave PTY
    if unsafe { libc::unlockpt(master_fd) } < 0 {
        panic!("{}", std::io::Error::last_os_error());
    }

    // Get the path to the slave PTY
    let slave_path_ptr = unsafe { libc::ptsname(master_fd) };
    if slave_path_ptr.is_null() {
        panic!("{}", std::io::Error::last_os_error());
    }

    // Open the slave PTY
    let slave_fd = unsafe { libc::open(slave_path_ptr, libc::O_RDWR) };
    if slave_fd < 0 {
        panic!("{}", std::io::Error::last_os_error());
    }

    unsafe { (Stdio::from_raw_fd(master_fd), Stdio::from_raw_fd(slave_fd)) }
}

#[cfg(unix)]
fn timestamps(metadata: std::fs::Metadata) -> (u64, u64) {
    use std::time::SystemTime;

    let atime = {
        let system_time = metadata.accessed().unwrap_or(SystemTime::UNIX_EPOCH);
        let duration = system_time.duration_since(SystemTime::UNIX_EPOCH).unwrap();
        duration.as_secs()
    };

    let modtime = {
        let system_time = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let duration = system_time.duration_since(SystemTime::UNIX_EPOCH).unwrap();
        duration.as_secs()
    };

    (atime, modtime)
}

fn command() -> Command {
    match env::var("RUNNER") {
        Ok(runner) if !runner.is_empty() => {
            let mut runner_args = runner.split(' ');
            let mut cmd = Command::new(runner_args.next().unwrap());
            cmd.args(runner_args);
            cmd.arg(bzip2_binary());

            cmd
        }
        _ => Command::new(bzip2_binary()),
    }
}

fn run_test(compressed: &str, expected: &[u8]) {
    let mut cmd = command();

    let output = match cmd
        .arg("-d")
        .arg(compressed)
        .arg("-c")
        .stdout(Stdio::piped())
        .output()
    {
        Ok(output) => output,
        Err(err) => panic!("Running {cmd:?} failed with {err:?}"),
    };

    assert!(
        output.status.success(),
        "status: {:?} stderr: {:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, expected);
}

#[test]
fn sample1() {
    run_test(
        "tests/input/quick/sample1.bz2",
        include_bytes!("input/quick/sample1.ref"),
    );
}

#[test]
fn sample2() {
    run_test(
        "tests/input/quick/sample2.bz2",
        include_bytes!("input/quick/sample2.ref"),
    );
}

#[test]
fn sample3() {
    run_test(
        "tests/input/quick/sample3.bz2",
        include_bytes!("input/quick/sample3.ref"),
    );
}

#[test]
fn flags_after_double_dash() {
    let mut cmd = command();

    expect_failure!(
        cmd.args(["--", "-V"]),
        if cfg!(windows) {
            "bzip2: Can't open input file -V: The system cannot find the file specified..\n"
        } else {
            "bzip2: Can't open input file -V: No such file or directory.\n"
        }
    );
}

#[test]
fn redundant_flag() {
    {
        let mut cmd = command();

        expect_success!(
            cmd.arg("--repetitive-best"),
            "bzip2: --repetitive-best is redundant in versions 0.9.5 and above\n"
        );
    }

    {
        let mut cmd = command();

        expect_success!(
            cmd.arg("--repetitive-fast"),
            "bzip2: --repetitive-fast is redundant in versions 0.9.5 and above\n"
        );
    }
}

#[test]
fn bad_flag() {
    {
        let mut cmd = command();
        cmd.arg("--foobar");
        let output = cmd.output().unwrap();

        assert!(!output.status.success(),);
        assert!(String::from_utf8_lossy(&output.stderr).contains("Bad flag `--foobar'"));
    }

    {
        let mut cmd = command();
        cmd.arg("-x");
        let output = cmd.output().unwrap();

        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("Bad flag `-x'"));
    }
}

#[test]
fn flags_from_env() {
    // a bad flag
    {
        let mut cmd = command();
        cmd.env("BZIP2", "-4 --foobar");
        let output = cmd.output().unwrap();

        assert!(
            !output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("Bad flag `--foobar'"));
    }

    {
        let mut cmd = command();

        expect_success!(
            cmd.env("BZIP", "-1 -4 --repetitive-fast"),
            "bzip2: --repetitive-fast is redundant in versions 0.9.5 and above\n"
        );
    }
}

#[test]
fn flags_from_env_ordering() {
    {
        let mut cmd = command();
        cmd.arg("--bad1");
        cmd.env("BZIP", "--bad2");
        cmd.env("BZIP2", "--bad3");
        let output = cmd.output().unwrap();

        assert!(
            !output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("Bad flag `--bad3'"));
    }

    {
        let mut cmd = command();
        cmd.arg("--bad1");
        cmd.env("BZIP", "--bad2");
        let output = cmd.output().unwrap();

        assert!(
            !output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("Bad flag `--bad2'"));
    }

    {
        let mut cmd = command();
        cmd.arg("--bad1");
        cmd.env("BZIP", "");
        cmd.env("BZIP2", "");
        let output = cmd.output().unwrap();

        assert!(
            !output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("Bad flag `--bad1'"));
    }
}

#[test]
fn license() {
    {
        let mut cmd = command();
        cmd.args(["-L", "--never-processed"]);
        let output = cmd.output().unwrap();

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("This program is free software"));
    }

    {
        let mut cmd = command();
        cmd.args(["--license", "--never-processed"]);
        let output = cmd.output().unwrap();

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("This program is free software"));
    }
}

#[test]
fn version() {
    // the version also just prints out the license text

    {
        let mut cmd = command();
        cmd.args(["-V", "--never-processed"]);
        let output = cmd.output().unwrap();

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("This program is free software"));
    }

    {
        let mut cmd = command();
        cmd.args(["--version", "--never-processed"]);
        let output = cmd.output().unwrap();

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("This program is free software"));
    }
}

#[test]
fn very_long_file_name() {
    let file_path = PathBuf::from("NaN".repeat(1000) + " batman!.txt");

    let mut cmd = command();

    expect_failure!(
        cmd.arg("-d").arg("-c").arg(&file_path),
        format!(
            concat!(
                "bzip2: file name\n",
                "`{file_path}'\n",
                "is suspiciously (more than 1024 chars) long.\n",
                "Try using a reasonable file name instead.  Sorry! :-)\n",
            ),
            file_path = file_path.display(),
        ),
    );
}

mod decompress_command {

    use super::*;

    #[test]
    fn stdin_to_stdout_unexpected_eof() {
        use std::io::Write;

        let compressed = include_bytes!("input/quick/sample1.bz2");

        let mut cmd = command();

        // Set up command to read from stdin, decompress, and output to stdout
        let mut child = cmd
            .arg("-d")
            .arg("-c")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start child process");

        // Write the compressed data to stdin
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(&compressed[..1024])
                .expect("Failed to write to stdin");
        }

        // Wait for the child process to finish and capture output
        let output = child.wait_with_output().expect("Failed to read stdout");

        expect_output_failure!(
            output,
            if cfg!(windows) {
                concat!(
                    "\n",
                    "bzip2: Compressed file ends unexpectedly;\n",
                    "	perhaps it is corrupted?  *Possible* reason follows.\n",
                    "bzip2: The handle is invalid.\n",
                    "	Input file = (stdin), output file = (stdout)\n",
                    "\n",
                    "It is possible that the compressed file(s) have become corrupted.\n",
                    "You can use the -tvv option to test integrity of such files.\n",
                    "\n",
                    "You can use the `bzip2recover' program to attempt to recover\n",
                    "data from undamaged sections of corrupted files.\n",
                    "\n",
                )
            } else {
                concat!(
                    "\n",
                    "bzip2: Compressed file ends unexpectedly;\n",
                    "	perhaps it is corrupted?  *Possible* reason follows.\n",
                    "bzip2: Inappropriate ioctl for device\n",
                    "	Input file = (stdin), output file = (stdout)\n",
                    "\n",
                    "It is possible that the compressed file(s) have become corrupted.\n",
                    "You can use the -tvv option to test integrity of such files.\n",
                    "\n",
                    "You can use the `bzip2recover' program to attempt to recover\n",
                    "data from undamaged sections of corrupted files.\n",
                    "\n",
                )
            },
        );
    }

    #[test]
    fn stdin_to_stdout_crc_error_i2o() {
        use std::io::Write;

        let compressed = include_bytes!("input/quick/sample1.bz2");

        let mut cmd = command();

        // Set up command to read from stdin, decompress, and output to stdout
        let mut child = cmd
            .arg("-d")
            .arg("-c")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start child process");

        let (left, right) = compressed.split_at(1024);

        // Write the compressed data to stdin
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(left).unwrap();
            stdin.write_all(b"garbage").unwrap();
            stdin.write_all(right).unwrap();
        }

        // Wait for the child process to finish and capture output
        let output = child.wait_with_output().expect("Failed to read stdout");

        expect_output_failure!(
            output,
            format!(concat!(
                "\n",
                "bzip2: Data integrity error when decompressing.\n",
                "\tInput file = (stdin), output file = (stdout)\n",
                "\n",
                "It is possible that the compressed file(s) have become corrupted.\n",
                "You can use the -tvv option to test integrity of such files.\n",
                "\n",
                "You can use the `bzip2recover' program to attempt to recover\n",
                "data from undamaged sections of corrupted files.\n",
                "\n",
            )),
        );
    }

    #[test]
    fn stdin_to_stdout_crc_error_f2f() {
        use std::io::Write;

        let compressed = include_bytes!("input/quick/sample1.bz2");

        let tmpdir = tempfile::tempdir().unwrap();
        let sample1 = tmpdir.path().join("sample1.bz2");

        {
            let mut f = std::fs::File::options()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&sample1)
                .unwrap();

            let (left, right) = compressed.split_at(1024);

            f.write_all(left).unwrap();
            f.write_all(b"garbage").unwrap();
            f.write_all(right).unwrap();
        }

        let mut cmd = command();

        expect_failure!(
            cmd.arg("-d").arg(sample1),
            format!(
                concat!(
                    "\n",
                    "bzip2: Data integrity error when decompressing.\n",
                    "\tInput file = {tmp_dir}/sample1.bz2, output file = {tmp_dir}/sample1\n",
                    "\n",
                    "It is possible that the compressed file(s) have become corrupted.\n",
                    "You can use the -tvv option to test integrity of such files.\n",
                    "\n",
                    "You can use the `bzip2recover' program to attempt to recover\n",
                    "data from undamaged sections of corrupted files.\n",
                    "\n",
                    "bzip2: Deleting output file {tmp_dir}/sample1, if it exists.\n",
                ),
                tmp_dir = tmpdir.path().display(),
            ),
        );
    }

    #[test]
    fn stdin_to_stdout() {
        use std::io::Write;

        let compressed = include_bytes!("input/quick/sample1.bz2");
        let expected = include_bytes!("input/quick/sample1.ref");

        let mut cmd = command();

        // Set up command to read from stdin, decompress, and output to stdout
        let mut child = cmd
            .arg("-d")
            .arg("-c")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to start child process");

        // Write the compressed data to stdin
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(compressed)
                .expect("Failed to write to stdin");
        }

        // Wait for the child process to finish and capture output
        let output = child.wait_with_output().expect("Failed to read stdout");

        assert!(
            output.status.success(),
            "status: {:?} stderr: {:?}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );

        assert_eq!(output.stdout, expected);
    }

    #[test]
    fn file_to_file_bz2() {
        let expected = include_bytes!("input/quick/sample1.ref");

        let tmpdir = tempfile::tempdir().unwrap();
        let sample1 = tmpdir.path().join("sample1.bz2");

        std::fs::copy("tests/input/quick/sample1.bz2", &sample1).unwrap();

        let mut cmd = command();

        expect_success!(cmd.arg("-d").arg(&sample1), "");

        let actual = std::fs::read(sample1.with_extension("")).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn file_to_file_tar() {
        let expected = include_bytes!("input/quick/sample1.ref");

        let tmpdir = tempfile::tempdir().unwrap();
        let sample1 = tmpdir.path().join("sample1.tbz2");

        std::fs::copy("tests/input/quick/sample1.bz2", &sample1).unwrap();

        let mut cmd = command();

        expect_success!(cmd.arg("-d").arg(&sample1), "");

        let actual = std::fs::read(sample1.with_extension("tar")).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn cannot_guess_file_name() {
        let expected = include_bytes!("input/quick/sample1.ref");

        let tmpdir = tempfile::tempdir().unwrap();
        let sample1 = tmpdir.path().join("sample1");

        std::fs::copy("tests/input/quick/sample1.bz2", &sample1).unwrap();

        let mut cmd = command();

        expect_success!(
            cmd.arg("-d").arg("-vvv").arg(&sample1),
            format!(
                concat!(
                    "bzip2: Can't guess original name for {in_file} -- using {in_file}.out\n",
                    "  {in_file}: \n",
                    "    [1: huff+mtf rt+rld {{0xccf1b5a5, 0xccf1b5a5}}]\n",
                    "    combined CRCs: stored = 0xccf1b5a5, computed = 0xccf1b5a5\n",
                    "    done\n",
                ),
                in_file = sample1.display(),
            ),
        );

        let actual = std::fs::read(sample1.with_extension("out")).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn input_file_does_not_exist() {
        let tmpdir = tempfile::tempdir().unwrap();
        let sample1 = tmpdir.path().join("sample1");

        let mut cmd = command();

        expect_failure!(
            cmd.arg("-d").arg("-vvv").arg(&sample1),
            if cfg!(windows) {
                format!(
                    "bzip2: Can't open input file {in_file}: \
                    The system cannot find the file specified..\n",
                    in_file = sample1.display(),
                )
            } else {
                format!(
                    "bzip2: Can't open input file {in_file}: No such file or directory.\n",
                    in_file = sample1.display(),
                )
            },
        );
    }

    #[test]
    fn input_file_is_a_directory() {
        let tmpdir = tempfile::tempdir().unwrap();

        let mut cmd = command();

        expect_failure!(
            cmd.arg("-d").arg("-vvv").arg(tmpdir.path()),
            format!(
                "bzip2: Input file {in_file} is a directory.\n",
                in_file = tmpdir.path().display(),
            ),
        );
    }

    #[test]
    #[cfg(unix)]
    fn input_file_is_a_symlink() {
        let tmpdir = tempfile::tempdir().unwrap();
        let sample1 = tmpdir.path().join("sample1.bz2");
        let symlink_path = tmpdir.path().join("this_is_a_symlink.bz2");

        std::fs::copy("tests/input/quick/sample1.bz2", &sample1).unwrap();

        std::os::unix::fs::symlink(sample1, &symlink_path).unwrap();

        let mut cmd = command();

        expect_failure!(
            cmd.arg("-d").arg("-vvv").arg(&symlink_path),
            format!(
                "bzip2: Input file {in_file} is not a normal file.\n",
                in_file = symlink_path.display(),
            ),
        );
    }

    #[test]
    #[cfg(unix)]
    fn input_file_has_hard_links() {
        let tmpdir = tempfile::tempdir().unwrap();
        let sample1 = tmpdir.path().join("sample1.bz2");
        let hardlink_path = tmpdir.path().join("this_is_a_symlink.bz2");

        std::fs::copy("tests/input/quick/sample1.bz2", &sample1).unwrap();

        std::fs::hard_link(sample1, &hardlink_path).unwrap();

        let mut cmd = command();

        expect_failure!(
            cmd.arg("-d").arg("-vvv").arg(&hardlink_path),
            format!(
                "bzip2: Input file {in_file} has 1 other link.\n",
                in_file = hardlink_path.display(),
            ),
        );
    }

    #[cfg(unix)]
    #[test]
    fn input_file_cannot_be_read_f2f() {
        use std::os::unix::fs::PermissionsExt;

        let tmpdir = tempfile::tempdir().unwrap();
        let sample1 = tmpdir.path().join("sample1.bz2");

        std::fs::copy("tests/input/quick/sample1.bz2", &sample1).unwrap();

        let mut permissions = std::fs::metadata(&sample1).unwrap().permissions();
        permissions.set_mode(0o000); // no permissions for you
        std::fs::set_permissions(&sample1, permissions).unwrap();

        let mut cmd = command();

        expect_failure!(
            cmd.arg("-d").arg("-vvv").arg(&sample1),
            format!(
                "bzip2: Can't open input file {in_file}: Permission denied.\n",
                in_file = sample1.display(),
            ),
        );
    }

    #[cfg(unix)]
    #[test]
    fn input_file_cannot_be_read_f2o() {
        use std::os::unix::fs::PermissionsExt;

        let tmpdir = tempfile::tempdir().unwrap();
        let sample1 = tmpdir.path().join("sample1.bz2");

        std::fs::copy("tests/input/quick/sample1.bz2", &sample1).unwrap();

        let mut permissions = std::fs::metadata(&sample1).unwrap().permissions();
        permissions.set_mode(0o000); // no permissions for you
        std::fs::set_permissions(&sample1, permissions).unwrap();

        let mut cmd = command();

        expect_failure!(
            cmd.arg("-d").arg(&sample1).arg("-c").stdout(Stdio::piped()),
            format!(
                "bzip2: Can't open input file {in_file}: Permission denied.\n",
                in_file = sample1.display()
            )
        );
    }

    #[test]
    #[cfg(unix)]
    fn output_file_cannot_be_written() {
        let tmpdir = tempfile::tempdir().unwrap();
        let sample1 = tmpdir.path().join("sample1.bz2");

        std::fs::copy("tests/input/quick/sample1.bz2", &sample1).unwrap();

        // make the directory readonly
        let mut permissions = std::fs::metadata(tmpdir.path()).unwrap().permissions();
        permissions.set_readonly(true); // no permissions for you
        std::fs::set_permissions(tmpdir.path(), permissions).unwrap();

        let mut cmd = command();

        expect_failure!(
            cmd.arg("-d").arg("-vvv").arg(&sample1),
            format!(
                "bzip2: Can't create output file {out_file}: Permission denied.\n",
                out_file = tmpdir.path().join("sample1").display(),
            ),
        );
    }

    #[test]
    #[cfg(unix)] // Timestamps are not restored on Windows
    fn output_file_exists() {
        use std::time::Duration;

        let expected = include_bytes!("input/quick/sample1.ref");

        let tmpdir = tempfile::tempdir().unwrap();

        let sample1_tar_bz2 = tmpdir.path().join("sample1.tar.bz2");
        std::fs::copy("tests/input/quick/sample1.bz2", &sample1_tar_bz2).unwrap();

        let sample1_tar = tmpdir.path().join("sample1.tar");
        std::fs::write(&sample1_tar, [1, 2, 3]).unwrap();

        let mut cmd = command();

        expect_failure!(
            cmd.arg("-d").arg("-vvv").arg(&sample1_tar_bz2),
            format!(
                "bzip2: Output file {out_file} already exists.\n",
                out_file = sample1_tar.display(),
            ),
        );

        let mut cmd = command();

        let input_metadata = std::fs::metadata(&sample1_tar_bz2).unwrap();

        // sleep so that we'd notice if the timestamp was not set correctly
        std::thread::sleep(Duration::from_millis(1700));

        expect_success!(
            cmd.arg("-d").arg("-vvvf").arg(&sample1_tar_bz2),
            format!(
                concat!(
                    "  {in_file}: \n",
                    "    [1: huff+mtf rt+rld {{0xccf1b5a5, 0xccf1b5a5}}]\n",
                    "    combined CRCs: stored = 0xccf1b5a5, computed = 0xccf1b5a5\n",
                    "    done\n",
                ),
                in_file = sample1_tar_bz2.display(),
            ),
        );

        let output_metadata = std::fs::metadata(&sample1_tar).unwrap();

        assert_eq!(timestamps(input_metadata), timestamps(output_metadata));

        let actual = std::fs::read(sample1_tar).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn input_file_is_not_bzip2_data_verbose() {
        let tmpdir = tempfile::tempdir().unwrap();

        let sample1 = tmpdir.path().join("sample1.txt");
        std::fs::write(&sample1, b"lang is it ompaad").unwrap();

        let mut cmd = command();

        expect_failure!(
            cmd.arg("-d").arg("-vvv").arg(&sample1),
            format!(
                concat!(
                    "bzip2: Can't guess original name for {in_file} -- using {in_file}.out\n",
                    "  {in_file}: not a bzip2 file.\n"
                ),
                in_file = sample1.display(),
            ),
        );
    }

    #[test]
    fn input_file_is_not_bzip2_data_less_verbose() {
        let tmpdir = tempfile::tempdir().unwrap();

        let sample1 = tmpdir.path().join("sample1.txt");
        std::fs::write(&sample1, b"lang is it ompaad").unwrap();

        let mut cmd = command();

        expect_failure!(
            cmd.arg("-d").arg(&sample1),
            format!(
                concat!(
                    "bzip2: Can't guess original name for {in_file} -- using {in_file}.out\n",
                    "bzip2: {in_file} is not a bzip2 file.\n",
                ),
                in_file = sample1.display(),
            ),
        );
    }

    #[test]
    fn input_file_is_not_bzip2_data_force_overwrite() {
        let tmpdir = tempfile::tempdir().unwrap();

        let sample1 = tmpdir.path().join("sample1.txt");
        std::fs::write(&sample1, b"lang is it ompaad").unwrap();

        let mut cmd = command();

        expect_success!(
            cmd.arg("-d").arg("-vvvf").arg(&sample1),
            format!(
                concat!(
                    "bzip2: Can't guess original name for {in_file} -- using {in_file}.out\n",
                    "  {in_file}: \n",
                    "    done\n",
                ),
                in_file = sample1.display(),
            ),
        );
    }

    #[test]
    fn second_input_file_is_not_bzip2_data() {
        use std::io::Write;

        let mut cmd = command();

        let mut child = cmd
            .arg("-d")
            .arg("-vvv")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start child process");

        // Write the compressed data to stdin
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(include_bytes!("input/quick/sample1.bz2"))
                .expect("Failed to write to stdin");

            stdin.write_all(b"lang is it ompaad").unwrap();
        }

        // Wait for the child process to finish and capture output
        let output = child.wait_with_output().expect("Failed to read stdout");

        expect_output_success!(
            output,
            format!(concat!(
                "  (stdin): \n",
                "    [1: huff+mtf rt+rld {{0xccf1b5a5, 0xccf1b5a5}}]\n",
                "    combined CRCs: stored = 0xccf1b5a5, computed = 0xccf1b5a5\n",
                "bzip2: (stdin): trailing garbage after EOF ignored\n",
                "done\n",
                ""
            ),),
        );
    }

    #[test]
    #[cfg(unix)]
    fn stdin_is_terminal() {
        let mut cmd = command();

        let (_master, tty) = setup_custom_tty();

        expect_failure!(
            cmd.arg("-d").arg("-c").stdin(tty),
            concat!(
                "bzip2: I won't read compressed data from a terminal.\n",
                "bzip2: For help, type: `bzip2 --help'.\n",
            ),
        );
    }
}

mod test_command {
    use super::*;

    #[test]
    fn stdout_and_test() {
        let mut cmd = command();

        expect_failure!(
            cmd.args(["-c", "-t"]),
            "bzip2: -c and -t cannot be used together.\n"
        );
    }

    #[test]
    #[cfg_attr(windows, ignore = "windows may be mangling stdin somehow")]
    fn valid_stdin() {
        use std::io::Write;

        let compressed = include_bytes!("input/quick/sample1.bz2");

        let mut cmd = command();

        // Set up command to read from stdin, decompress, and output to stdout
        let mut child = cmd
            .arg("-t")
            .arg("-v")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start child process");

        // Write the compressed data to stdin
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(compressed)
                .expect("Failed to write to stdin");
        }

        // Wait for the child process to finish and capture output
        let output = child.wait_with_output().expect("Failed to read stdout");

        expect_output_success!(output, "  (stdin): ok\n");
    }

    #[test]
    fn invalid_stdin() {
        use std::io::Write;

        let mut cmd = command();

        // Set up command to read from stdin, decompress, and output to stdout
        let mut child = cmd
            .arg("-t")
            .arg("-v")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start child process");

        // Write the random data to stdin
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(b"fee stjert, sibben stjerre")
                .expect("Failed to write to stdin");
        }

        // Wait for the child process to finish and capture output
        let output = child.wait_with_output().expect("Failed to read stdout");

        expect_output_failure!(
            output,
            concat!(
                "  (stdin): bad magic number (file not created by bzip2)\n",
                "\n",
                "You can use the `bzip2recover' program to attempt to recover\n",
                "data from undamaged sections of corrupted files.\n",
                "\n"
            ),
        );
    }

    #[test]
    fn file() {
        let tmpdir = tempfile::tempdir().unwrap();
        let sample1 = tmpdir.path().join("sample1.bz2");

        std::fs::copy("tests/input/quick/sample1.bz2", &sample1).unwrap();

        let mut cmd = command();

        expect_success!(cmd.arg("-t").arg(&sample1), "");
    }

    #[test]
    fn files() {
        let tmpdir = tempfile::tempdir().unwrap();
        let sample1 = tmpdir.path().join("sample1.bz2");
        let longer = tmpdir.path().join("a_longer_file_name.bz2");

        std::fs::copy("tests/input/quick/sample1.bz2", &sample1).unwrap();
        std::fs::copy("tests/input/quick/sample1.bz2", &longer).unwrap();

        let mut cmd = command();

        expect_success!(
            cmd.arg("-t").arg("-v").arg(&sample1).arg(&longer),
            format!(
                concat!(
                    "  {in_dir}/sample1.bz2:            ok\n",
                    "  {in_dir}/a_longer_file_name.bz2: ok\n",
                ),
                in_dir = tmpdir.path().display(),
            )
        );
    }

    #[test]
    fn input_file_does_not_exist() {
        let tmpdir = tempfile::tempdir().unwrap();
        let sample1 = tmpdir.path().join("sample1");

        let mut cmd = command();

        expect_failure!(
            cmd.arg("-t").arg("-vvv").arg(&sample1),
            if cfg!(windows) {
                format!(
                    "bzip2: Can't open input {in_file}: \
                    The system cannot find the file specified..\n",
                    in_file = sample1.display(),
                )
            } else {
                format!(
                    "bzip2: Can't open input {in_file}: No such file or directory.\n",
                    in_file = sample1.display(),
                )
            },
        );
    }

    #[test]
    fn input_file_is_a_directory() {
        let tmpdir = tempfile::tempdir().unwrap();

        let mut cmd = command();

        expect_failure!(
            cmd.arg("-t").arg("-vvv").arg(tmpdir.path()),
            format!(
                "bzip2: Input file {in_file} is a directory.\n",
                in_file = tmpdir.path().display(),
            ),
        );
    }

    #[cfg(unix)]
    #[test]
    fn input_file_cannot_be_read() {
        use std::os::unix::fs::PermissionsExt;

        let tmpdir = tempfile::tempdir().unwrap();
        let sample1 = tmpdir.path().join("sample1.bz2");

        std::fs::copy("tests/input/quick/sample1.bz2", &sample1).unwrap();

        let mut permissions = std::fs::metadata(&sample1).unwrap().permissions();
        permissions.set_mode(0o000); // no permissions for you
        std::fs::set_permissions(&sample1, permissions).unwrap();

        let mut cmd = command();

        expect_failure!(
            cmd.arg("-t").arg("-vvv").arg(&sample1),
            format!(
                "bzip2: Can't open input {in_file}: Permission denied.\n",
                in_file = sample1.display(),
            ),
        );
    }

    #[test]
    #[cfg(unix)]
    fn stdin_is_terminal() {
        let mut cmd = command();

        let (_master, tty) = setup_custom_tty();

        expect_failure!(
            cmd.arg("-t").stdin(tty),
            concat!(
                "bzip2: I won't read compressed data from a terminal.\n",
                "bzip2: For help, type: `bzip2 --help'.\n",
            ),
        );
    }
}

mod compress_command {
    use super::*;

    #[test]
    fn test_comp_decomp_sample_ref1() {
        let sample = Path::new("tests/input/quick/sample1.ref");

        for block_size in ["-1", "-2", "-3"] {
            let mut cmd = command();
            cmd.arg("--compress")
                .arg(block_size)
                .arg("--keep")
                .arg("--stdout")
                .arg(sample)
                .stdout(Stdio::piped());

            let output = cmd.output().unwrap();

            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );

            let tmpdir = tempfile::tempdir().unwrap();

            let tempfile_path = tmpdir
                .path()
                .with_file_name(sample.file_name().unwrap())
                .with_extension("bz2");

            std::fs::write(&tempfile_path, output.stdout).unwrap();

            let mut cmd = command();
            cmd.arg("--decompress")
                .arg("--stdout")
                .arg(tempfile_path)
                .stdout(Stdio::piped());

            let output = cmd.output().unwrap();

            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );

            let out_hash = crc32fast::hash(&output.stdout);
            let ref_file = std::fs::read(sample).unwrap();
            let ref_hash = crc32fast::hash(&ref_file);

            assert_eq!(out_hash, ref_hash);
        }
    }

    #[test]
    fn test_comp_decomp_sample_ref2() {
        let sample = Path::new("tests/input/quick/sample2.ref");

        for block_size in ["-1", "-2", "-3"] {
            let mut cmd = command();
            cmd.arg("--compress")
                .arg(block_size)
                .arg("--keep")
                .arg("--stdout")
                .arg(sample)
                .stdout(Stdio::piped());

            let output = cmd.output().unwrap();

            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );

            let tmpdir = tempfile::tempdir().unwrap();

            let tempfile_path = tmpdir
                .path()
                .with_file_name(sample.file_name().unwrap())
                .with_extension("bz2");

            std::fs::write(&tempfile_path, output.stdout).unwrap();

            let mut cmd = command();
            cmd.arg("--decompress")
                .arg("--stdout")
                .arg(tempfile_path)
                .stdout(Stdio::piped());

            let output = cmd.output().unwrap();

            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );

            let out_hash = crc32fast::hash(&output.stdout);
            let ref_file = std::fs::read(sample).unwrap();
            let ref_hash = crc32fast::hash(&ref_file);

            assert_eq!(out_hash, ref_hash);
        }
    }

    #[test]
    fn test_comp_decomp_sample_ref3() {
        let sample = Path::new("tests/input/quick/sample3.ref");

        for block_size in ["-1", "-2", "-3"] {
            let mut cmd = command();
            cmd.arg("--compress")
                .arg(block_size)
                .arg("--keep")
                .arg("--stdout")
                .arg(sample)
                .stdout(Stdio::piped());

            let output = cmd.output().unwrap();

            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );

            let tmpdir = tempfile::tempdir().unwrap();

            let tempfile_path = tmpdir
                .path()
                .with_file_name(sample.file_name().unwrap())
                .with_extension("bz2");

            std::fs::write(&tempfile_path, output.stdout).unwrap();

            let mut cmd = command();
            cmd.arg("--decompress")
                .arg("--stdout")
                .arg(tempfile_path)
                .stdout(Stdio::piped());

            let output = cmd.output().unwrap();

            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );

            let out_hash = crc32fast::hash(&output.stdout);
            let ref_file = std::fs::read(sample).unwrap();
            let ref_hash = crc32fast::hash(&ref_file);

            assert_eq!(out_hash, ref_hash);
        }
    }

    #[test]
    fn compression_stderr_output() {
        let sample = Path::new("tests/input/quick/sample3.ref");

        let mut cmd = command();
        expect_success!(
            cmd.arg("--compress")
                .arg("-1")
                .arg("--keep")
                .arg("--stdout")
                .arg("-v")
                .arg(sample)
                .stdout(Stdio::piped()),
            format!(
                "  {in_file}: 440.454:1,  0.018 bits/byte, 99.77% saved, 120244 in, 273 out.\n",
                in_file = sample.display(),
            ),
        );

        let mut cmd = command();
        expect_success!(
            cmd.arg("--compress")
                .arg("-1")
                .arg("--keep")
                .arg("--stdout")
                .arg("-vv")
                .arg(sample)
                .stdout(Stdio::piped()),
            format!(
                concat!(
                    "  {in_file}: \n",
                    "    block 1: crc = 0xbcd1d34c, combined CRC = 0xbcd1d34c, size = 99981\n",
                    "    too repetitive; using fallback sorting algorithm\n",
                    "    block 2: crc = 0xabd59416, combined CRC = 0xd276328f, size = 20263\n",
                    "    too repetitive; using fallback sorting algorithm\n",
                    "    final combined CRC = 0xd276328f\n",
                    "   440.454:1,  0.018 bits/byte, 99.77% saved, 120244 in, 273 out.\n",
                ),
                in_file = sample.display(),
            ),
        );

        let mut cmd = command();
        expect_success!(
            cmd.arg("--compress")
                .arg("-1")
                .arg("--keep")
                .arg("--stdout")
                .arg("-vvv")
                .arg(sample)
                .stdout(Stdio::piped()),
            format!(
                concat!(
                    "  {in_file}: \n",
                    "    block 1: crc = 0xbcd1d34c, combined CRC = 0xbcd1d34c, size = 99981\n",
                    "      901380 work, 99981 block, ratio  9.02\n",
                    "    too repetitive; using fallback sorting algorithm\n",
                    "      99981 in block, 292 after MTF & 1-2 coding, 32+2 syms in use\n",
                    "      initial group 3, [0 .. 2], has 114 syms (39.0%)\n",
                    "      initial group 2, [3 .. 9], has 85 syms (29.1%)\n",
                    "      initial group 1, [10 .. 33], has 93 syms (31.8%)\n",
                    "      pass 1: size is 296, grp uses are 2 0 4 \n",
                    "      pass 2: size is 155, grp uses are 2 0 4 \n",
                    "      pass 3: size is 155, grp uses are 2 0 4 \n",
                    "      pass 4: size is 155, grp uses are 2 0 4 \n",
                    "      bytes: mapping 19, selectors 3, code lengths 30, codes 155\n",
                    "    block 2: crc = 0xabd59416, combined CRC = 0xd276328f, size = 20263\n",
                    "      182372 work, 20263 block, ratio  9.00\n",
                    "    too repetitive; using fallback sorting algorithm\n",
                    "      20263 in block, 54 after MTF & 1-2 coding, 4+2 syms in use\n",
                    "      initial group 2, [0 .. 1], has 48 syms (88.9%)\n",
                    "      initial group 1, [2 .. 5], has 6 syms (11.1%)\n",
                    "      pass 1: size is 11, grp uses are 0 2 \n",
                    "      pass 2: size is 12, grp uses are 0 2 \n",
                    "      pass 3: size is 12, grp uses are 0 2 \n",
                    "      pass 4: size is 12, grp uses are 0 2 \n",
                    "      bytes: mapping 11, selectors 2, code lengths 5, codes 12\n",
                    "    final combined CRC = 0xd276328f\n",
                    "   440.454:1,  0.018 bits/byte, 99.77% saved, 120244 in, 273 out.\n",
                ),
                in_file = sample.display(),
            )
        );
    }

    #[test]
    fn input_file_does_not_exist() {
        let tmpdir = tempfile::tempdir().unwrap();
        let sample1 = tmpdir.path().join("sample1.tar");

        let mut cmd = command();

        expect_failure!(
            cmd.arg("-z").arg("-vvv").arg(&sample1),
            if cfg!(windows) {
                format!(
                    "bzip2: Can't open input file {in_file}: \
                    The system cannot find the file specified..\n",
                    in_file = sample1.display(),
                )
            } else {
                format!(
                    "bzip2: Can't open input file {in_file}: No such file or directory.\n",
                    in_file = sample1.display(),
                )
            },
        );
    }

    #[test]
    fn input_file_is_a_directory() {
        let tmpdir = tempfile::tempdir().unwrap();

        let mut cmd = command();

        expect_failure!(
            cmd.arg("-z").arg("-vvv").arg(tmpdir.path()),
            format!(
                "bzip2: Input file {in_file} is a directory.\n",
                in_file = tmpdir.path().display(),
            ),
        );
    }

    #[test]
    #[cfg(unix)]
    fn input_file_is_a_symlink() {
        let tmpdir = tempfile::tempdir().unwrap();
        let sample1 = tmpdir.path().join("sample1.tar");
        let symlink_path = tmpdir.path().join("this_is_a_symlink.tar");

        std::fs::copy("tests/input/quick/sample1.bz2", &sample1).unwrap();

        std::os::unix::fs::symlink(sample1, &symlink_path).unwrap();

        let mut cmd = command();

        expect_failure!(
            cmd.arg("-z").arg("-vvv").arg(&symlink_path),
            format!(
                "bzip2: Input file {in_file} is not a normal file.\n",
                in_file = symlink_path.display(),
            ),
        );
    }

    #[test]
    #[cfg(unix)]
    fn input_file_has_hard_links() {
        let tmpdir = tempfile::tempdir().unwrap();
        let sample1 = tmpdir.path().join("sample1.tar");
        let hardlink_path = tmpdir.path().join("this_is_a_symlink.tar");

        std::fs::copy("tests/input/quick/sample1.ref", &sample1).unwrap();

        std::fs::hard_link(sample1, &hardlink_path).unwrap();

        let mut cmd = command();

        expect_failure!(
            cmd.arg("-z").arg("-vvv").arg(&hardlink_path),
            format!(
                "bzip2: Input file {in_file} has 1 other link.\n",
                in_file = hardlink_path.display(),
            ),
        );
    }

    #[cfg(unix)]
    #[test]
    fn input_file_cannot_be_read_f2f() {
        use std::os::unix::fs::PermissionsExt;

        let tmpdir = tempfile::tempdir().unwrap();
        let sample1 = tmpdir.path().join("sample1.tar");

        std::fs::copy("tests/input/quick/sample1.ref", &sample1).unwrap();

        let mut permissions = std::fs::metadata(&sample1).unwrap().permissions();
        permissions.set_mode(0o000); // no permissions for you
        std::fs::set_permissions(&sample1, permissions).unwrap();

        let mut cmd = command();

        expect_failure!(
            cmd.arg("-z").arg("-vvv").arg(&sample1),
            format!(
                "bzip2: Can't open input file {in_file}: Permission denied.\n",
                in_file = sample1.display(),
            ),
        );
    }

    #[cfg(unix)]
    #[test]
    fn input_file_cannot_be_read_f2o() {
        use std::os::unix::fs::PermissionsExt;

        let tmpdir = tempfile::tempdir().unwrap();
        let sample1 = tmpdir.path().join("sample1.tar");

        std::fs::copy("tests/input/quick/sample1.ref", &sample1).unwrap();

        let mut permissions = std::fs::metadata(tmpdir.path()).unwrap().permissions();
        permissions.set_mode(0o000); // no permissions for you
        std::fs::set_permissions(tmpdir.path(), permissions).unwrap();

        let mut cmd = command();

        cmd.arg("-z").arg(&sample1).arg("-c").stdout(Stdio::piped());

        let output = match cmd.output() {
            Ok(output) => output,
            Err(err) => panic!("Running {cmd:?} failed with {err:?}"),
        };

        assert!(
            !output.status.success(),
            "status is success (expected failure): {:?} stderr: {:?}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.stdout.is_empty(),
            "stdout: {:?}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(String::from_utf8_lossy(&output.stderr)
            .replace(bzip2_binary(), "bzip2")
            .contains(&format!(
                "bzip2: Can't open input file {in_file}: ",
                in_file = sample1.display()
            )));
    }

    #[test]
    fn input_has_bz2_extension() {
        let tmpdir = tempfile::tempdir().unwrap();

        for extension in ["bz2", "bz", "tbz2", "tbz"] {
            let sample1 = tmpdir.path().join("test").with_extension(extension);

            std::fs::copy("tests/input/quick/sample1.bz2", &sample1).unwrap();

            let mut cmd = command();

            expect_failure!(
                cmd.arg("-z").arg(&sample1).arg("-c").stdout(Stdio::piped()),
                format!(
                    "bzip2: Input file {in_file} already has {extension} suffix.\n",
                    in_file = sample1.display(),
                    extension = extension,
                )
            );
        }
    }

    #[test]
    #[cfg(unix)] // Timestamps are not restored on Windows
    fn output_file_exists() {
        use std::time::Duration;

        let tmpdir = tempfile::tempdir().unwrap();

        let sample1_ref = tmpdir.path().join("sample1.ref");
        std::fs::copy("tests/input/quick/sample1.ref", &sample1_ref).unwrap();

        let sample1_bz2 = tmpdir.path().join("sample1.ref.bz2");
        std::fs::write(&sample1_bz2, [1, 2, 3]).unwrap();

        let mut cmd = command();

        expect_failure!(
            cmd.arg("-z")
                .arg("-vvv")
                .arg("-k")
                .arg(&sample1_ref)
                .stderr(Stdio::piped()),
            format!(
                "bzip2: Output file {in_file}.bz2 already exists.\n",
                in_file = sample1_ref.display(),
            ),
        );

        let mut cmd = command();

        let input_metadata = std::fs::metadata(&sample1_ref).unwrap();

        // sleep so that we'd notice if the timestamp was not set correctly
        std::thread::sleep(Duration::from_millis(1700));

        expect_success!(
            cmd.arg("-z").arg("-vvvf").arg(&sample1_ref),
            format!(
                concat!(
                    "  {in_file}: \n",
                    "    block 1: crc = 0xccf1b5a5, combined CRC = 0xccf1b5a5, size = 98170\n",
                    "      431 work, 98170 block, ratio  0.00\n",
                    "      98170 in block, 59500 after MTF & 1-2 coding, 256+2 syms in use\n",
                    "      initial group 6, [0 .. 0], has 12672 syms (21.3%)\n",
                    "      initial group 5, [1 .. 1], has 5883 syms ( 9.9%)\n",
                    "      initial group 4, [2 .. 3], has 15621 syms (26.3%)\n",
                    "      initial group 3, [4 .. 6], has 7857 syms (13.2%)\n",
                    "      initial group 2, [7 .. 15], has 8958 syms (15.1%)\n",
                    "      initial group 1, [16 .. 257], has 8509 syms (14.3%)\n",
                    "      pass 1: size is 72279, grp uses are 219 211 68 486 13 193 \n",
                    "      pass 2: size is 31631, grp uses are 193 273 94 385 62 183 \n",
                    "      pass 3: size is 31524, grp uses are 190 256 131 361 67 185 \n",
                    "      pass 4: size is 31510, grp uses are 179 256 139 355 69 192 \n",
                    "      bytes: mapping 37, selectors 324, code lengths 463, codes 31498\n",
                    "    final combined CRC = 0xccf1b5a5\n",
                    "    3.051:1,  2.622 bits/byte, 67.22% saved, 98696 in, 32348 out.\n",
                ),
                in_file = sample1_ref.display(),
            ),
        );

        let output_metadata = std::fs::metadata(&sample1_bz2).unwrap();

        assert_eq!(timestamps(input_metadata), timestamps(output_metadata));

        // just to make sure the permissions are set correctly
        let _ = std::fs::read(sample1_bz2).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn stdout_is_terminal_i2o() {
        let mut cmd = command();

        let (_master, tty) = setup_custom_tty();

        expect_failure!(
            cmd.arg("-z").arg("-c").stdin(Stdio::piped()).stdout(tty),
            concat!(
                "bzip2: I won't write compressed data to a terminal.\n",
                "bzip2: For help, type: `bzip2 --help'.\n",
            ),
        );
    }

    #[test]
    #[cfg(unix)]
    fn stdout_is_terminal_f2o() {
        let mut cmd = command();

        let tmpdir = tempfile::tempdir().unwrap();

        let sample1_ref = tmpdir.path().join("sample1.ref");
        std::fs::copy("tests/input/quick/sample1.ref", &sample1_ref).unwrap();

        let (_master, tty) = setup_custom_tty();

        expect_failure!(
            cmd.arg("-z")
                .arg("-c")
                .arg("-k")
                .arg(&sample1_ref)
                .stdout(tty),
            concat!(
                "bzip2: I won't write compressed data to a terminal.\n",
                "bzip2: For help, type: `bzip2 --help'.\n",
            ),
        );

        // the `-k` flag should keep the input file
        assert!(sample1_ref.exists());
    }

    #[test]
    #[cfg(unix)]
    fn io_error() {
        use std::os::fd::FromRawFd;

        let mut cmd = command();

        let tmpdir = tempfile::tempdir().unwrap();

        let sample1_ref = tmpdir.path().join("sample1.ref");
        std::fs::copy("tests/input/quick/sample1.ref", &sample1_ref).unwrap();

        let mut pair = [0; 2];
        unsafe {
            assert_eq!(libc::pipe(&mut pair as *mut [i32; 2] as *mut i32), 0);
            // closing the read side here triggers an IO error down the line
            assert_eq!(libc::close(pair[0]), 0);
        }

        expect_failure!(
            cmd.arg("-z")
                .arg("-c")
                .arg("-k")
                .arg(&sample1_ref)
                .stdout(unsafe { Stdio::from_raw_fd(pair[1]) }),
            format!(
                concat!(
                    "\n",
                    "bzip2: I/O or other error, bailing out.  Possible reason follows.\n",
                    "bzip2: Broken pipe\n",
                    "\tInput file = {in_file}, output file = (stdout)\n",
                    ""
                ),
                in_file = sample1_ref.display(),
            )
        );

        // the `-k` flag should keep the input file
        assert!(sample1_ref.exists());
    }

    #[test]
    fn compress_sample1_log() {
        let mut cmd = command();

        expect_success!(
            cmd.arg("-z")
                .arg("-vvvv")
                .arg("-c")
                .arg("-k")
                .arg("tests/input/quick/sample1.ref"),
            include_str!("compress-sample1-log.txt"),
        );
    }
}
