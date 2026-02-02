// Copyright 2021-2026 Kyle Schreiber
// SPDX-License-Identifier: BSD-3-Clause

//! # Terminal utilities
//!
//! Use the [`prompt_password_tty`] function to read a password from the tty.
//!
//! Use the [`isatty`] function to check if the given stream
//! is a tty.
//!
//! ## Features
//! Enable the `secure_zero` feature to zero out data read from the tty.

mod tty;

#[cfg(target_family = "windows")]
mod win32;

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
#[allow(dead_code)]
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
    #[cfg(feature = "secure_zero")]
    let mut data_read = zeroize::Zeroizing::new(Vec::<u8>::new());
    #[cfg(feature = "secure_zero")]
    let mut buffer = zeroize::Zeroizing::new([0u8; 64]);

    #[cfg(not(feature = "secure_zero"))]
    let mut data_read = Vec::<u8>::new();
    #[cfg(not(feature = "secure_zero"))]
    let mut buffer: [u8; 64] = [0; 64];

    loop {
        let n = match source.read(buffer.as_mut()) {
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

    let password = match std::str::from_utf8(&data_read) {
        Ok(p) => p.to_string(),
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
    use crate::win32::{
        GetConsoleMode, GetStdHandle, ReadConsoleW, SetConsoleMode, WriteConsoleW,
        ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
    };
    use crate::win32::{BOOL, ENABLE_ECHO_INPUT, FALSE, INVALID_HANDLE_VALUE, STD_INPUT_HANDLE};
    use crate::{print_stream, PromptError, Stream};

    use std::fs::OpenOptions;
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::raw::HANDLE;

    // Disable echo for the given handle. Returns the original bits
    // of the console mode.
    fn disable_echo(handle: HANDLE) -> Result<u32, PromptError> {
        let mut mode: u32 = 0;
        unsafe {
            if GetConsoleMode(handle, &mut mode) == FALSE {
                return Err(PromptError::IOError(std::io::Error::last_os_error()));
            }
        }
        let original_mode = mode;

        mode &= !ENABLE_ECHO_INPUT;
        mode &= !ENABLE_LINE_INPUT;
        mode |= ENABLE_PROCESSED_INPUT;

        unsafe {
            if SetConsoleMode(handle, mode) == FALSE {
                let err = std::io::Error::last_os_error();
                return Err(PromptError::IOError(err));
            }
        }

        Ok(original_mode)
    }

    // Re-enable echo. orig must be the data return from the previous
    // call to disable_echo
    fn enable_echo(orig: u32, handle: HANDLE) -> Result<(), PromptError> {
        unsafe {
            if SetConsoleMode(handle, orig) == FALSE {
                let err = std::io::Error::last_os_error();
                return Err(PromptError::EnableFailed(err));
            }
        }

        Ok(())
    }

    /// Write the optional prompt to the specified stream.
    /// Reads the password from STDIN. Does not include the newline.
    /// The stream must be Stdout or Stderr
    ///
    /// An error will be returned if echo could not be disabled. The most
    /// common cause of this will be that stdin was piped in. Callers should
    /// generally call [`crate::isatty`] to check if stdin was redirected to
    /// avoid this.
    ///
    /// # Examples
    /// ```no_run
    /// // A typical use case would be to write the prompt to stderr and read
    /// // the password from stdin when the output of the application is
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

        let handle: HANDLE = unsafe {
            let handle = GetStdHandle(STD_INPUT_HANDLE);
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                let err = std::io::Error::last_os_error();
                return Err(PromptError::IOError(err));
            }

            handle
        };

        // Always try to disable terminal echo, if we can't stdin was
        // probably piped in. Callers should check that stdin isatty.
        let restore = disable_echo(handle)?;

        if let Some(p) = prompt {
            print_stream(p, stream)?;
        }

        let password = match read_console(handle) {
            Ok(p) => p,
            Err(e) => {
                enable_echo(restore, handle)?;
                print_stream("\n", stream)?;
                return Err(e);
            }
        };

        enable_echo(restore, handle)?;
        print_stream("\n", stream)?;

        Ok(password)
    }

    /// Write the optional prompt to the tty and read input from the tty
    /// Returns the String input (excluding newline)
    pub fn prompt_password_tty(prompt: Option<&str>) -> Result<String, PromptError> {
        let console_in = OpenOptions::new().read(true).write(true).open("CONIN$")?;
        let console_out = OpenOptions::new().write(true).open("CONOUT$")?;

        if let Some(p) = prompt {
            write_console(console_out.as_raw_handle(), p)?;
        }

        let restore = disable_echo(console_in.as_raw_handle())?;
        let password = match read_console(console_in.as_raw_handle()) {
            Ok(p) => p,
            Err(e) => {
                enable_echo(restore, console_in.as_raw_handle())?;
                write_console(console_out.as_raw_handle(), "\r\n")?;
                return Err(e);
            }
        };

        enable_echo(restore, console_in.as_raw_handle())?;
        write_console(console_out.as_raw_handle(), "\r\n")?;

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

    fn contains_crlf(input: &[u16]) -> bool {
        let cr = 0x000d;
        let lf = 0x000a;
        for i in input {
            if *i == cr || *i == lf {
                return true;
            }
        }
        false
    }

    // Returns the given input with \r, \n, \b removed
    fn ignore_ctrl_chars(input: &[u16]) -> Vec<u16> {
        let cr = 0x000d;
        let lf = 0x000a;
        let bs = 0x0008;
        let mut res: Vec<u16> = Vec::with_capacity(input.len());
        // For each backspace encountered, remove the previous entry.
        for i in input {
            let val = *i;
            if val == cr || val == lf {
                return res;
            }
            if val == bs {
                res.pop();
            } else {
                res.push(val);
            }
        }

        res
    }

    /// Read from the console
    fn read_console(console_in: HANDLE) -> Result<String, PromptError> {
        #[cfg(feature = "secure_zero")]
        use zeroize::Zeroize;

        #[cfg(feature = "secure_zero")]
        let mut input = zeroize::Zeroizing::new(Vec::<u16>::new());
        #[cfg(feature = "secure_zero")]
        let mut buffer = zeroize::Zeroizing::new([0u16; 64]);

        #[cfg(not(feature = "secure_zero"))]
        let mut input: Vec<u16> = Vec::new();
        #[cfg(not(feature = "secure_zero"))]
        let mut buffer: [u16; 1] = [0; 1];

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

            let chars = &buffer[..max_len];
            input.extend_from_slice(chars);
            if contains_crlf(chars) {
                break;
            }
        }

        #[cfg(feature = "secure_zero")]
        let mut cleaned_input = ignore_ctrl_chars(input.as_slice());

        #[cfg(not(feature = "secure_zero"))]
        let cleaned_input = ignore_ctrl_chars(input.as_slice());

        let password = match String::from_utf16(&cleaned_input) {
            Ok(s) => s,
            Err(_) => {
                let err =
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "Found invalid UTF-16");
                return Err(PromptError::IOError(err));
            }
        };

        #[cfg(feature = "secure_zero")]
        cleaned_input.zeroize();

        Ok(password)
    }
}

#[cfg(target_family = "unix")]
mod unix {
    use crate::{print_stream, read_line, strip_newline, PromptError, Stream};

    use libc::{tcgetattr, tcsetattr, termios, ECHO, STDIN_FILENO, TCSANOW};
    use std::ffi::CStr;
    use std::fs::File;
    use std::io::Write;
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, FromRawFd};

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
    /// ```no_run
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

        // Disable terminal echo
        set_echo(false, STDIN_FILENO)?;

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

                set_echo(true, STDIN_FILENO)?;
                return Err(PromptError::IOError(e));
            }
        };

        if prompt.is_some() {
            print_stream("\n", stream)?;
        }

        // Re-enable terminal echo
        set_echo(true, STDIN_FILENO)?;

        let pass = strip_newline(&pass).to_string();

        Ok(pass)
    }

    /// Write the optional prompt to the tty and read input from the tty
    /// Returns the String input (excluding newline)
    pub fn prompt_password_tty(prompt: Option<&str>) -> Result<String, PromptError> {
        let flags = if prompt.is_some() {
            libc::O_RDWR | libc::O_NOCTTY
        } else {
            libc::O_RDONLY | libc::O_NOCTTY
        };

        let raw_tty = unsafe {
            libc::open(
                CStr::from_bytes_with_nul_unchecked(b"/dev/tty\0").as_ptr(),
                flags,
            )
        };

        if raw_tty == -1 {
            let err = std::io::Error::last_os_error();
            return Err(PromptError::IOError(err));
        }

        let mut tty = unsafe { File::from_raw_fd(raw_tty) };

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

        #[cfg(feature = "secure_zero")]
        let password = zeroize::Zeroizing::new(password);

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
    use super::{find_lf, read_line, strip_newline};

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
    fn test_read_line() -> Result<(), String> {
        let line = "Hello\n".to_string();
        let pass = match read_line(line.as_bytes()) {
            Ok(p) => p,
            Err(e) => return Err(e.to_string()),
        };
        assert_eq!(pass, line);

        Ok(())
    }

    #[test]
    #[cfg_attr(not(feature = "secure_zero"), ignore)]
    fn test_read_line_secure_zero() -> Result<(), String> {
        let line = "Hello\n".to_string();
        let pass = match read_line(line.as_bytes()) {
            Ok(p) => p,
            Err(e) => return Err(e.to_string()),
        };
        assert_eq!(pass, line);

        Ok(())
    }
}
