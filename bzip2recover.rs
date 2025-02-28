use std::fs::File;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const BZ_MAX_HANDLED_BLOCKS: usize = 50000;
const BZ_MAX_FILENAME: usize = 2000;

const BLOCK_HEADER_HI: u32 = 0x00003141u32;
const BLOCK_HEADER_LO: u32 = 0x59265359u32;

const BLOCK_ENDMARK_HI: u32 = 0x00001772u32;
const BLOCK_ENDMARK_LO: u32 = 0x45385090u32;

enum Error {
    Reading(std::io::Error),
    Writing(std::io::Error),
    TooManyBlocks(usize),
    Fatal,
}

struct BitStream {
    handle: File,
    buffer: i32,
    buff_live: i32,
    mode: u8,
}

impl BitStream {
    fn open_read_stream(stream: File) -> Self {
        Self {
            handle: stream,
            buffer: 0,
            buff_live: 0,
            mode: b'r',
        }
    }

    fn open_write_stream(stream: File) -> Self {
        Self {
            handle: stream,
            buffer: 0,
            buff_live: 0,
            mode: b'w',
        }
    }

    fn close(mut self) -> Result<(), Error> {
        if self.mode == b'w' {
            while self.buff_live < 8 {
                self.buff_live += 1;
                self.buffer <<= 1;
            }
            self.handle
                .write_all(&[self.buffer as u8])
                .map_err(Error::Writing)?;
            self.handle.flush().map_err(Error::Writing)?;
        }

        Ok(())
    }

    fn get_bit(&mut self) -> Result<Option<bool>, Error> {
        if self.buff_live > 0 {
            self.buff_live -= 1;

            Ok(Some((self.buffer >> self.buff_live) & 0x1 != 0))
        } else {
            let mut ret_val = [0u8];
            let n = self.handle.read(&mut ret_val).map_err(Error::Reading)?;

            // EOF
            if n == 0 {
                return Ok(None);
            }

            self.buff_live = 7;
            self.buffer = ret_val[0] as i32;

            Ok(Some((self.buffer >> 7) & 0x1 != 0))
        }
    }

    fn put_bit(&mut self, bit: i32) -> Result<(), Error> {
        if self.buff_live == 8 {
            self.handle
                .write_all(&[self.buffer as u8])
                .map_err(Error::Writing)?;
            self.buff_live = 1;
            self.buffer = bit & 0x1;
        } else {
            self.buffer = (self.buffer << 1) | bit & 0x1;
            self.buff_live += 1;
        }

        Ok(())
    }

    fn put_u8(&mut self, c: u8) -> Result<(), Error> {
        for i in (0..8).rev() {
            self.put_bit(((c as u32 >> i) & 0x1) as i32)?;
        }

        Ok(())
    }

    fn put_u32(&mut self, c: u32) -> Result<(), Error> {
        for i in (0..32).rev() {
            self.put_bit(((c >> i) & 0x1) as i32)?;
        }

        Ok(())
    }
}

struct EmitError<'a> {
    program_name: &'a Path,
    in_filename: &'a Path,
    error: Error,
}

impl core::fmt::Display for EmitError<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.error {
            Error::Reading(ref io_error) => {
                writeln!(
                    f,
                    "{}: I/O error reading `{}', possible reason follows.",
                    self.program_name.display(),
                    self.in_filename.display(),
                )?;

                writeln!(f, "{}", io_error)?;

                writeln!(
                    f,
                    "{}: warning: output file(s) may be incomplete.",
                    self.program_name.display(),
                )?;

                Ok(())
            }
            Error::Writing(ref io_error) => {
                writeln!(
                    f,
                    "{}: I/O error writing `{}', possible reason follows.",
                    self.program_name.display(),
                    self.in_filename.display(),
                )?;

                writeln!(f, "{}", io_error)?;

                writeln!(
                    f,
                    "{}: warning: output file(s) may be incomplete.",
                    self.program_name.display(),
                )?;

                Ok(())
            }
            Error::TooManyBlocks(max_handled_blocks) => {
                let program_name = self.program_name.display();

                writeln!(
                    f,
                    "{}: `{}' appears to contain more than {max_handled_blocks} blocks",
                    program_name,
                    self.in_filename.display(),
                )?;

                writeln!(
                    f,
                    "{program_name}: and cannot be handled.  To fix, increase"
                )?;
                writeln!(
                    f,
                    "{program_name}: BZ_MAX_HANDLED_BLOCKS in bzip2recover.rs, and recompile."
                )?;

                Ok(())
            }
            Error::Fatal => Ok(()),
        }
    }
}

fn main_help(program_name: &Path, in_filename: &Path) -> Result<(), Error> {
    let mut b_start = vec![0u64; BZ_MAX_HANDLED_BLOCKS];
    let mut b_end = vec![0u64; BZ_MAX_HANDLED_BLOCKS];
    let mut rb_start = vec![0u64; BZ_MAX_HANDLED_BLOCKS];
    let mut rb_end = vec![0u64; BZ_MAX_HANDLED_BLOCKS];

    let progname = program_name.display();

    if in_filename.as_os_str().len() >= BZ_MAX_FILENAME - 20 {
        eprintln!(
            "{}: supplied filename is suspiciously (>= {} chars) long.  Bye!",
            program_name.display(),
            in_filename.as_os_str().len(),
        );

        return Err(Error::Fatal);
    }

    let Ok(input_file) = std::fs::File::options().read(true).open(in_filename) else {
        eprintln!("{}: can't read `{}'", progname, in_filename.display());

        return Err(Error::Fatal);
    };

    let mut input_bitstream = BitStream::open_read_stream(input_file);
    eprintln!("{}: searching for block boundaries ...", progname);

    let mut bits_read: u64 = 0;
    let mut buff_lo: u32 = 0;
    let mut buff_hi = buff_lo;
    let mut current_block = 0;
    b_start[current_block] = 0;
    let mut rb_ctr = 0;

    loop {
        let b = input_bitstream.get_bit()?;
        bits_read = bits_read.wrapping_add(1);
        match b {
            None => {
                if bits_read >= b_start[current_block]
                    && bits_read.wrapping_sub(b_start[current_block]) >= 40
                {
                    b_end[current_block] = bits_read.wrapping_sub(1);
                    if current_block > 0 {
                        eprintln!(
                            "   block {} runs from {} to {} (incomplete)",
                            current_block, b_start[current_block], b_end[current_block],
                        );
                    }
                }
                break;
            }
            Some(b) => {
                buff_hi = (buff_hi << 1) | (buff_lo >> 31);
                buff_lo = (buff_lo << 1) | b as u32;
                if (buff_hi & 0xffff) == BLOCK_HEADER_HI && buff_lo == BLOCK_HEADER_LO
                    || (buff_hi & 0xffff) == BLOCK_ENDMARK_HI && buff_lo == BLOCK_ENDMARK_LO
                {
                    b_end[current_block] = if bits_read > 49 {
                        bits_read.wrapping_sub(49)
                    } else {
                        0
                    };

                    if current_block > 0
                        && (b_end[current_block]).wrapping_sub(b_start[current_block]) >= 130
                    {
                        eprintln!(
                            "   block {} runs from {} to {}",
                            rb_ctr + 1,
                            b_start[current_block],
                            b_end[current_block],
                        );
                        rb_start[rb_ctr] = b_start[current_block];
                        rb_end[rb_ctr] = b_end[current_block];
                        rb_ctr += 1;
                    }
                    if current_block >= BZ_MAX_HANDLED_BLOCKS {
                        return Err(Error::TooManyBlocks(BZ_MAX_HANDLED_BLOCKS));
                    }
                    current_block += 1;
                    b_start[current_block] = bits_read;
                }
            }
        }
    }

    input_bitstream.close()?;

    /*-- identified blocks run from 1 to rbCtr inclusive. --*/

    if rb_ctr < 1 {
        eprintln!("{}: sorry, I couldn't find any block boundaries.", progname);

        return Err(Error::Fatal);
    }

    eprintln!("{}: splitting into blocks", progname);

    let Ok(input_file) = std::fs::File::options().read(true).open(in_filename) else {
        eprintln!("{}: can't read `{}'", progname, in_filename.display());

        return Err(Error::Fatal);
    };
    input_bitstream = BitStream::open_read_stream(input_file);

    let mut block_crc: u32 = 0;
    let mut output_bitstream: Option<BitStream> = None;
    let mut wr_block = 0;

    bits_read = 0;

    loop {
        let Some(b) = input_bitstream.get_bit()? else {
            // EOF
            break;
        };

        buff_hi = (buff_hi << 1) | (buff_lo >> 31);
        buff_lo = (buff_lo << 1) | b as u32;

        if bits_read == 47u64.wrapping_add(rb_start[wr_block]) {
            block_crc = (buff_hi << 16) | (buff_lo >> 16);
        }
        if bits_read >= rb_start[wr_block] && bits_read <= rb_end[wr_block] {
            if let Some(output_bitstream) = output_bitstream.as_mut() {
                output_bitstream.put_bit(b as i32)?;
            }
        }
        bits_read = bits_read.wrapping_add(1);
        if bits_read == (rb_end[wr_block]).wrapping_add(1) {
            if let Some(mut output_bitstream) = output_bitstream.take() {
                output_bitstream.put_u8(0x17)?;
                output_bitstream.put_u8(0x72)?;
                output_bitstream.put_u8(0x45)?;
                output_bitstream.put_u8(0x38)?;
                output_bitstream.put_u8(0x50)?;
                output_bitstream.put_u8(0x90)?;
                output_bitstream.put_u32(block_crc)?;
                output_bitstream.close()?;
            }

            if wr_block >= rb_ctr {
                break;
            }
            wr_block += 1;
        } else if bits_read == rb_start[wr_block] {
            // we've been able to open this file, so there must be a file name
            let filename = in_filename.file_name().unwrap();

            let filename = format!("rec{:05}{}", wr_block + 1, filename.to_string_lossy());

            let out_filename = in_filename.with_file_name(&filename).with_extension("bz2");

            eprintln!(
                "   writing block {} to `{}' ...",
                wr_block + 1,
                out_filename.display(),
            );

            let mut options = std::fs::File::options();
            options.write(true).create_new(true);

            #[cfg(unix)]
            #[allow(clippy::unnecessary_cast)]
            options.mode(libc::S_IWUSR as u32 | libc::S_IRUSR as u32);

            let Ok(output_file) = options.open(&out_filename) else {
                eprintln!("{}: can't write `{}'", progname, out_filename.display());

                return Err(Error::Fatal);
            };

            output_bitstream = {
                let mut output_bitstream = BitStream::open_write_stream(output_file);
                output_bitstream.put_u8(0x42)?;
                output_bitstream.put_u8(0x5a)?;
                output_bitstream.put_u8(0x68)?;
                output_bitstream.put_u8(0x30 + 9)?;
                output_bitstream.put_u8(0x31)?;
                output_bitstream.put_u8(0x41)?;
                output_bitstream.put_u8(0x59)?;
                output_bitstream.put_u8(0x26)?;
                output_bitstream.put_u8(0x53)?;
                output_bitstream.put_u8(0x59)?;
                Some(output_bitstream)
            }
        }
    }

    eprintln!("{}: finished", progname);

    Ok(())
}

fn main() -> ExitCode {
    let mut it = ::std::env::args_os();

    let program_name = PathBuf::from(it.next().unwrap());
    let opt_in_filename = it.next().map(PathBuf::from);

    eprintln!("bzip2recover 1.0.6: extracts blocks from damaged .bz2 files.");

    let Some(in_filename) = opt_in_filename else {
        eprintln!(
            "{program_name}: usage is `{program_name} damaged_file_name'.",
            program_name = program_name.display()
        );

        eprintln!("\trestrictions on size of recovered file: None");

        return ExitCode::FAILURE;
    };

    match main_help(&program_name, &in_filename) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let emit_error = EmitError {
                program_name: &program_name,
                in_filename: &in_filename,
                error,
            };

            eprint!("{}", emit_error);

            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn read_error() {
        use std::fmt::Write;

        let program_name = Path::new("/foo/bar/bzip2recover");
        let in_filename = Path::new("$garbage");

        let io_error = std::fs::File::open(in_filename).unwrap_err();
        let emit_error = EmitError {
            program_name,
            in_filename,
            error: Error::Reading(io_error),
        };

        let mut buf = String::new();
        write!(&mut buf, "{}", emit_error).unwrap();

        assert_eq!(
            buf,
            if cfg!(windows) {
                concat!(
                    "/foo/bar/bzip2recover: I/O error reading `$garbage', possible reason follows.\n",
                    "The system cannot find the file specified. (os error 2)\n",
                    "/foo/bar/bzip2recover: warning: output file(s) may be incomplete.\n"
                )
            } else {
                concat!(
                    "/foo/bar/bzip2recover: I/O error reading `$garbage', possible reason follows.\n",
                    "No such file or directory (os error 2)\n",
                    "/foo/bar/bzip2recover: warning: output file(s) may be incomplete.\n"
                )
            }
        );
    }

    #[test]
    fn write() {
        use std::fmt::Write;

        let program_name = Path::new("/foo/bar/bzip2recover");
        let in_filename = Path::new("$garbage");

        let io_error = std::fs::File::open(in_filename).unwrap_err();
        let emit_error = EmitError {
            program_name,
            in_filename,
            error: Error::Writing(io_error),
        };

        let mut buf = String::new();
        write!(&mut buf, "{}", emit_error).unwrap();

        assert_eq!(
            buf,
            if cfg!(windows) {
                concat!(
                    "/foo/bar/bzip2recover: I/O error writing `$garbage', possible reason follows.\n",
                    "The system cannot find the file specified. (os error 2)\n",
                    "/foo/bar/bzip2recover: warning: output file(s) may be incomplete.\n"
                )
            } else {
                concat!(
                    "/foo/bar/bzip2recover: I/O error writing `$garbage', possible reason follows.\n",
                    "No such file or directory (os error 2)\n",
                    "/foo/bar/bzip2recover: warning: output file(s) may be incomplete.\n"
                )
            }
        );
    }

    #[test]
    fn too_many_blocks() {
        use std::fmt::Write;

        let program_name = Path::new("/foo/bar/bzip2recover");
        let in_filename = Path::new("$garbage");

        let emit_error = EmitError {
            program_name,
            in_filename,
            error: Error::TooManyBlocks(42),
        };

        let mut buf = String::new();
        write!(&mut buf, "{}", emit_error).unwrap();

        assert_eq!(
            buf,
            concat!(
                "/foo/bar/bzip2recover: `$garbage' appears to contain more than 42 blocks\n",
                "/foo/bar/bzip2recover: and cannot be handled.  To fix, increase\n",
                "/foo/bar/bzip2recover: BZ_MAX_HANDLED_BLOCKS in bzip2recover.rs, and recompile.\n"
            )
        );
    }
}
