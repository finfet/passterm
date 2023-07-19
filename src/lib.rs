// Copyright 2021-2023 Kyle Schreiber
// SPDX-License-Identifier: BSD-3-Clause

//! Terminal utilities
//!
//! Use the [`read_password()`] function to read a line from stdin with
//! echo disabled.
//!
//! Use the [`isatty()`] function to check if the given stream
//! is a tty.

mod tty;

pub use crate::tty::Stream;
use std::error::Error;
use std::io::Read;

#[cfg(target_family = "windows")]
pub use crate::windows::prompt_password_stdin;

#[cfg(target_family = "windows")]
pub use crate::windows::prompt_password_tty;

#[cfg(target_family = "windows")]
pub use crate::tty::isatty;

#[cfg(target_family = "unix")]
pub use crate::unix::prompt_password_stdin;

#[cfg(target_family = "unix")]
pub use crate::unix::prompt_password_tty;

#[cfg(target_family = "unix")]
pub use crate::tty::isatty;

/// Returned if there is an issue getting user input from STDIN or if echo
/// could not be disabled.
///
/// [`PromptError::EnableFailed`] is more serious and is returned when
/// echo was was successfully disabled, but could not be re-enabled. Future
/// terminal output may not echo properly if this error is not handled.
#[derive(Debug)]
pub enum PromptError {
    EnableFailed(std::io::Error),
    IOError(std::io::Error),
    InvalidArgument,
}

impl std::fmt::Display for PromptError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            PromptError::EnableFailed(e) => write!(f, "Could not re-enable echo: {}", e),
            PromptError::IOError(e) => e.fmt(f),
            PromptError::InvalidArgument => write!(f, "Invalid arugment Stdin"),
        }
    }
}

impl From<std::io::Error> for PromptError {
    fn from(e: std::io::Error) -> PromptError {
        PromptError::IOError(e)
    }
}

impl Error for PromptError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            PromptError::EnableFailed(e) => Some(e),
            PromptError::IOError(e) => Some(e),
            PromptError::InvalidArgument => None,
        }
    }
}

/// Write the prompt to the specified [`crate::tty:Steam`]
fn print_stream(prompt: &str, stream: Stream) -> Result<(), PromptError> {
    use std::io::Write;

    if stream == Stream::Stdout {
        print!("{}", prompt);
        std::io::stdout().flush()?;
    } else {
        eprint!("{}", prompt);
        std::io::stderr().flush()?;
    }

    Ok(())
}

/// Strip the trailing newline
fn strip_newline(input: &str) -> &str {
    input
        .strip_suffix("\r\n")
        .or(input.strip_suffix('\n'))
        .unwrap_or(input)
}

/// Searches the slice for a CRLF or LF byte sequence. If a CRLF or only LF
/// is found, return its position.

#[allow(dead_code)]
fn find_crlf(input: &[u16]) -> Option<usize> {
    let cr: u16 = 0x000d;
    let lf: u16 = 0x000a;
    let mut prev: Option<u16> = None;
    for (i, c) in input.iter().enumerate() {
        if *c == lf {
            if prev.is_some_and(|p| p == cr) {
                return Some(i - 1);
            } else {
                return Some(i);
            }
        }

        prev = Some(*c)
    }

    None
}

/// Read data from the buffer until a LF (0x0a) character is found.
/// Returns the data as a string (including newline). Note that the input
/// data must contain an LF or this function will loop indefinitely.
///
/// Returns an error if the data is invalid UTF-8.
#[allow(dead_code)]
fn read_line<T: Read>(mut source: T) -> Result<String, std::io::Error> {
    let mut data_read = Vec::<u8>::new();
    let mut buffer: [u8; 64] = [0; 64];
    loop {
        let n = match source.read(&mut buffer) {
            Ok(n) => n,
            Err(e) => match e.kind() {
                std::io::ErrorKind::Interrupted => continue,
                _ => {
                    return Err(e);
                }
            },
        };

        if let Some(pos) = find_lf(&buffer[..n]) {
            data_read.extend_from_slice(&buffer[..pos + 1]);
            break;
        } else {
            data_read.extend_from_slice(&buffer[..n]);
        }
    }

    let password = match String::from_utf8(data_read) {
        Ok(p) => p,
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Found invalid UTF-8",
            ));
        }
    };

    Ok(password)
}

/// Find a LF (0x0a) in the specified buffer.
/// If found, returns the position of the LF
#[allow(dead_code)]
fn find_lf(input: &[u8]) -> Option<usize> {
    let lf: u8 = 0x0a;
    for (i, b) in input.iter().enumerate() {
        if *b == lf {
            return Some(i);
        }
    }

    None
}

#[cfg(target_family = "windows")]
mod windows {
    use crate::{find_crlf, print_stream, strip_newline, PromptError, Stream};

    use windows_sys::Win32::Foundation::{
        CloseHandle, BOOL, FALSE, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{CreateFileA, GetFileType, OPEN_EXISTING};
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, ReadConsoleW, SetConsoleMode, WriteConsoleW, CONSOLE_MODE,
        ENABLE_ECHO_INPUT, STD_INPUT_HANDLE,
    };

    struct HandleCloser(HANDLE);

    impl Drop for HandleCloser {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    fn set_echo(echo: bool, handle: HANDLE) -> Result<(), PromptError> {
        let mut mode: CONSOLE_MODE = 0;
        unsafe {
            if GetConsoleMode(handle, &mut mode as *mut CONSOLE_MODE) == FALSE {
                return Err(PromptError::IOError(std::io::Error::last_os_error()));
            }
        }

        if !echo {
            mode &= !ENABLE_ECHO_INPUT;
        } else {
            mode |= ENABLE_ECHO_INPUT;
        }

        unsafe {
            if SetConsoleMode(handle, mode) == FALSE {
                let err = std::io::Error::last_os_error();
                if echo {
                    return Err(PromptError::EnableFailed(err));
                } else {
                    return Err(PromptError::IOError(err));
                }
            }
        }

        Ok(())
    }

    /// Write the optional prompt to the specified stream.
    /// Reads the password from STDIN. Does not include the newline.
    /// The stream must be Stdout or Stderr
    ///
    /// # Examples
    /// ```
    /// // A typical use case would be to write the prompt to stderr and read
    /// // the password from stdin while the output of the application is
    /// // directed to stdout.
    /// use passterm::{isatty, Stream, prompt_password_stdin};
    /// if !isatty(Stream::Stdout) {
    ///     let pass = prompt_password_stdin(Some("Password: "), Stream::Stderr)?;
    /// }
    /// ```
    pub fn prompt_password_stdin(
        prompt: Option<&str>,
        stream: Stream,
    ) -> Result<String, PromptError> {
        if stream == Stream::Stdin {
            return Err(PromptError::InvalidArgument);
        }

        let handle: HANDLE = unsafe {
            let handle = GetStdHandle(STD_INPUT_HANDLE);
            if handle == INVALID_HANDLE_VALUE {
                let err = std::io::Error::last_os_error();
                return Err(PromptError::IOError(err));
            }

            handle
        };

        let _handle_closer = HandleCloser(handle);

        let console = unsafe {
            // FILE_TYPE_CHAR is 0x0002 which is a console
            // NOTE: In the past on mysys2 terminals like git bash on windows
            // the file type comes back as FILE_TYPE_PIPE 0x03. This means
            // that we can't tell if we're in a pipe or a console, so echo
            // won't be disabled at all.
            GetFileType(handle) == windows_sys::Win32::Storage::FileSystem::FILE_TYPE_CHAR
        };

        // Disable terminal echo if we're in a console, if we're not,
        // stdin was probably piped in.
        if console {
            set_echo(false, handle)?;
        }

        if let Some(p) = prompt {
            print_stream(p, stream)?;
        }

        // The rust docs for std::io::Stdin note that windows does not
        // support non UTF-8 byte sequences.
        let mut pass = String::new();
        let stdin = std::io::stdin();
        match stdin.read_line(&mut pass) {
            Ok(_) => {}
            Err(e) => {
                if prompt.is_some() {
                    print_stream("\n", stream)?;
                }

                if console {
                    set_echo(true, handle)?;
                }
                return Err(PromptError::IOError(e));
            }
        };

        if prompt.is_some() {
            print_stream("\n", stream)?;
        }

        if console {
            // Re-enable termianal echo.
            set_echo(true, handle)?;
        }

        let pass = strip_newline(&pass).to_string();

        Ok(pass)
    }

    /// Write the optional prompt to the tty and read input from the tty
    /// Returns the String input (excluding newline)
    pub fn prompt_password_tty(prompt: Option<&str>) -> Result<String, PromptError> {
        let console_in: HANDLE = unsafe {
            let handle = CreateFileA(
                b"CONIN$\x00".as_ptr(), // null terminated name
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                0,
            );
            if handle == INVALID_HANDLE_VALUE {
                let err = std::io::Error::last_os_error();
                return Err(PromptError::IOError(err));
            }

            handle
        };

        let _console_in_closer = HandleCloser(console_in);

        let console_out: Option<HANDLE> = if prompt.is_some() {
            let console_out: HANDLE = unsafe {
                let handle = CreateFileA(
                    b"CONOUT$\x00".as_ptr(), // null terminated name
                    GENERIC_WRITE,
                    0,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    0,
                    0,
                );
                if handle == INVALID_HANDLE_VALUE {
                    let err = std::io::Error::last_os_error();
                    return Err(PromptError::IOError(err));
                }

                handle
            };

            Some(console_out)
        } else {
            None
        };

        let _console_out_closer: Option<HandleCloser> = match console_out {
            Some(c) => Some(HandleCloser(c)),
            None => None,
        };

        if prompt.is_some() {
            write_console(console_out.unwrap(), prompt.unwrap())?;
        }

        set_echo(false, console_in)?;
        let password = match read_console(console_in) {
            Ok(p) => p,
            Err(e) => {
                if prompt.is_some() {
                    // Write a \r\n to the console because echo was disabled.
                    let crlf = String::from_utf8(vec![0x0d, 0x0a]).unwrap();
                    if let Err(e) = write_console(console_out.unwrap(), &crlf) {
                        set_echo(true, console_in)?;
                        return Err(e);
                    }
                }
                set_echo(true, console_in)?;
                return Err(e);
            }
        };

        if prompt.is_some() {
            // Write a \r\n to the console because echo was disabled.
            let crlf = String::from_utf8(vec![0x0d, 0x0a]).unwrap();
            if let Err(e) = write_console(console_out.unwrap(), &crlf) {
                set_echo(true, console_in)?;
                return Err(e);
            }
        }

        set_echo(true, console_in)?;

        let password = strip_newline(&password).to_string();

        Ok(password)
    }

    /// Write to the console
    fn write_console(console_out: HANDLE, prompt: &str) -> Result<(), PromptError> {
        // We have to convert to UTF-16 first because of the Windows API
        let converted_prompt: Vec<u16> = prompt.encode_utf16().collect();
        let res: BOOL = unsafe {
            WriteConsoleW(
                console_out,
                converted_prompt.as_ptr() as *const core::ffi::c_void,
                converted_prompt.len() as u32,
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };

        if res == FALSE {
            let err = std::io::Error::last_os_error();
            return Err(PromptError::IOError(err));
        }

        Ok(())
    }

    /// Read from the console
    fn read_console(console_in: HANDLE) -> Result<String, PromptError> {
        let mut input: Vec<u16> = Vec::new();
        let mut buffer: [u16; 64] = [0; 64];

        loop {
            let mut num_read: u32 = 0;
            let num_read_ptr: *mut u32 = &mut num_read;
            let res: BOOL = unsafe {
                ReadConsoleW(
                    console_in,
                    buffer.as_mut_ptr() as *mut std::ffi::c_void,
                    buffer.len() as u32,
                    num_read_ptr,
                    std::ptr::null(),
                )
            };

            if res == FALSE {
                let err = std::io::Error::last_os_error();
                return Err(PromptError::IOError(err));
            }

            let max_len = std::cmp::min(num_read, buffer.len() as u32) as usize;
            if let Some(pos) = find_crlf(&buffer[..max_len]) {
                input.extend_from_slice(&buffer[..pos]);
                break;
            } else {
                input.extend_from_slice(&buffer[..max_len])
            }
        }

        let password = match String::from_utf16(&input) {
            Ok(s) => s,
            Err(_) => {
                let err =
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "Found invalid UTF-16");
                return Err(PromptError::IOError(err));
            }
        };

        Ok(password)
    }
}

#[cfg(target_family = "unix")]
mod unix {
    use crate::{print_stream, read_line, strip_newline, PromptError, Stream};

    use libc::{tcgetattr, tcsetattr, termios, ECHO, STDIN_FILENO, TCSANOW};
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;

    fn set_echo(echo: bool, fd: i32) -> Result<(), PromptError> {
        let mut tty = MaybeUninit::<termios>::uninit();
        unsafe {
            if tcgetattr(fd, tty.as_mut_ptr()) != 0 {
                return Err(PromptError::IOError(std::io::Error::last_os_error()));
            }
        }

        let mut tty = unsafe { tty.assume_init() };

        if !echo {
            tty.c_lflag &= !ECHO;
        } else {
            tty.c_lflag |= ECHO;
        }

        unsafe {
            let tty_ptr: *const termios = &tty;
            if tcsetattr(fd, TCSANOW, tty_ptr) != 0 {
                let err = std::io::Error::last_os_error();
                if echo {
                    return Err(PromptError::EnableFailed(err));
                } else {
                    return Err(PromptError::IOError(err));
                }
            }
        }

        Ok(())
    }

    /// Write the optional prompt to the specified stream.
    /// Reads the password from STDIN. Does not include the newline.
    /// The stream must be Stdout or Stderr
    ///
    /// # Examples
    /// ```
    /// // A typical use case would be to write the prompt to stderr and read
    /// // the password from stdin while the output of the application is
    /// // directed to stdout.
    /// use passterm::{isatty, Stream, prompt_password_stdin};
    /// if !isatty(Stream::Stdout) {
    ///     let pass = prompt_password_stdin(Some("Password: "), Stream::Stderr).unwrap();
    /// }
    /// ```
    pub fn prompt_password_stdin(
        prompt: Option<&str>,
        stream: Stream,
    ) -> Result<String, PromptError> {
        if stream == Stream::Stdin {
            return Err(PromptError::InvalidArgument);
        }

        let is_tty = unsafe { libc::isatty(STDIN_FILENO) == 1 };

        if is_tty {
            // Disable terminal echo
            set_echo(false, STDIN_FILENO)?;
        }

        if let Some(p) = prompt {
            print_stream(p, stream)?;
        }

        let mut pass = String::new();
        let stdin = std::io::stdin();
        match stdin.read_line(&mut pass) {
            Ok(_) => {}
            Err(e) => {
                if prompt.is_some() {
                    print_stream("\n", stream)?;
                }

                if is_tty {
                    set_echo(true, STDIN_FILENO)?;
                }
                return Err(PromptError::IOError(e));
            }
        };

        if prompt.is_some() {
            print_stream("\n", stream)?;
        }

        if is_tty {
            // Re-enable terminal echo
            set_echo(true, STDIN_FILENO)?;
        }

        let pass = strip_newline(&pass).to_string();

        Ok(pass)
    }

    /// Write the optional prompt to the tty and read input from the tty
    /// Returns the String input (excluding newline)
    pub fn prompt_password_tty(prompt: Option<&str>) -> Result<String, PromptError> {
        let mut tty = OpenOptions::new()
            .read(true)
            .write(prompt.is_some())
            .open("/dev/tty")?;
        if let Some(p) = prompt {
            write_tty(p, &mut tty)?;
        }

        let tty_fd = tty.as_raw_fd();
        set_echo(false, tty_fd)?;
        let password = match read_line(&mut tty) {
            Ok(p) => p,
            Err(e) => {
                if prompt.is_some() {
                    if let Err(e) = write_tty("\n", &mut tty) {
                        set_echo(true, tty_fd)?;
                        return Err(e.into());
                    }
                }
                set_echo(true, tty_fd)?;
                return Err(e.into());
            }
        };

        if prompt.is_some() {
            if let Err(e) = write_tty("\n", &mut tty) {
                set_echo(true, tty_fd)?;
                return Err(e.into());
            }
        }

        set_echo(true, tty_fd)?;

        let password = strip_newline(&password).to_string();

        Ok(password)
    }

    fn write_tty<T: Write>(prompt: &str, tty: &mut T) -> Result<(), std::io::Error> {
        tty.write_all(prompt.as_bytes())?;
        tty.flush()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{find_crlf, find_lf, read_line, strip_newline};

    #[test]
    fn test_strip_newline() {
        assert_eq!(strip_newline("hello\r\n"), "hello");
        assert_eq!(strip_newline("hello\n"), "hello");
        assert_eq!(strip_newline("hello"), "hello");
    }

    #[test]
    fn test_find_lf() {
        let input = [0x41, 0x42, 0x43, 0x0a];
        let input2 = [0x41, 0x42, 0x43];
        assert_eq!(find_lf(&input), Some(3));
        assert_eq!(find_lf(&input2), None);
    }

    #[test]
    fn test_find_crlf() {
        let input = [0x006d, 0x0075, 0x0073, 0x0069, 0x0063, 0x000d, 0x000a];
        let input2 = [0x006d, 0x0075, 0x0073, 0x0069, 0x0063];
        assert_eq!(find_crlf(&input), Some(5));
        assert_eq!(find_crlf(&input2), None);
    }

    #[test]
    fn test_read_line() -> Result<(), String> {
        let line = "Hello\n".to_string();
        let pass = match read_line(line.as_bytes()) {
            Ok(p) => p,
            Err(e) => return Err(e.to_string()),
        };
        assert_eq!(pass, line);

        Ok(())
    }
}
