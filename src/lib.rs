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

pub use crate::windows::prompt_password_tty;
#[cfg(target_family = "windows")]
pub use crate::windows::read_password_stdin;

#[cfg(target_family = "windows")]
pub use crate::tty::isatty;

#[cfg(target_family = "unix")]
pub use crate::unix::read_password_stdin;

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
}

impl std::fmt::Display for PromptError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            PromptError::EnableFailed(e) => write!(f, "Could not re-enable echo: {}", e),
            PromptError::IOError(e) => e.fmt(f),
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
        }
    }
}

#[cfg(target_family = "windows")]
mod windows {
    use crate::PromptError;
    use windows_sys::Win32::Foundation::{BOOL, FALSE, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileA, GetFileType, OPEN_EXISTING};
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, ReadConsoleW, SetConsoleMode, WriteConsoleW, CONSOLE_MODE,
        ENABLE_ECHO_INPUT, STD_INPUT_HANDLE,
    };

    fn set_stdin_echo(echo: bool, handle: HANDLE) -> Result<(), PromptError> {
        let mut mode: CONSOLE_MODE = 0;
        unsafe {
            if GetConsoleMode(handle, &mut mode as *mut CONSOLE_MODE) == 0 {
                return Err(PromptError::IOError(std::io::Error::last_os_error()));
            }
        }

        if !echo {
            mode &= !ENABLE_ECHO_INPUT;
        } else {
            mode |= ENABLE_ECHO_INPUT;
        }

        unsafe {
            if SetConsoleMode(handle, mode) == 0 {
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

    /// Read a password from STDIN. Does not include the newline.
    pub fn read_password_stdin() -> Result<String, PromptError> {
        // The rust docs for std::io::Stdin note that windows does not
        // support non UTF-8 byte sequences.
        let mut pass = String::new();

        let handle: HANDLE = unsafe {
            let handle = GetStdHandle(STD_INPUT_HANDLE);
            if handle == INVALID_HANDLE_VALUE {
                let err = std::io::Error::last_os_error();
                return Err(PromptError::IOError(err));
            }

            handle
        };

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
            set_stdin_echo(false, handle)?;
        }

        let stdin = std::io::stdin();
        match stdin.read_line(&mut pass) {
            Ok(_) => {}
            Err(e) => {
                if console {
                    set_stdin_echo(true, handle)?;
                }
                return Err(PromptError::IOError(e));
            }
        };

        pass = pass.trim().to_string();

        if console {
            // Re-enable termianal echo.
            set_stdin_echo(true, handle)?;
        }

        Ok(pass)
    }

    /// Write the prompt to the tty and read input from the tty
    /// Returns the String input (excluding newline)
    pub fn prompt_password_tty(prompt: &str) -> Result<String, PromptError> {
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

        write_console(console_out, prompt)?;
        set_stdin_echo(false, console_in)?;
        let password = match read_console(console_in) {
            Ok(p) => p,
            Err(e) => {
                // Write a \r\n to the console because echo was disabled.
                let crlf = String::from_utf8(vec![0x0d, 0x0a]).unwrap();
                if let Err(e) = write_console(console_out, &crlf) {
                    set_stdin_echo(true, console_in)?;
                    return Err(e);
                }
                set_stdin_echo(true, console_in)?;
                return Err(e);
            }
        };

        // Write a \r\n to the console because echo was disabled.
        let crlf = String::from_utf8(vec![0x0d, 0x0a]).unwrap();
        if let Err(e) = write_console(console_out, &crlf) {
            set_stdin_echo(true, console_in)?;
            return Err(e);
        }

        set_stdin_echo(true, console_in)?;

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
        // TODO: Zero out these buffers at the end of the function
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

            let max_chars = std::cmp::min(num_read, buffer.len() as u32) as usize;
            let mut done = false;
            for c in buffer.iter().take(max_chars) {
                let cr: u16 = 0x000d;
                let lf: u16 = 0x000a;
                if *c == cr || *c == lf {
                    done = true;
                    break;
                }
                input.push(*c);
            }

            if done {
                break;
            }
        }

        let password = String::from_utf16(&input).expect("Found invalid UTF-16 data");

        Ok(password)
    }
}

#[cfg(target_family = "unix")]
mod unix {
    use libc::{tcgetattr, tcsetattr, termios, ECHO, STDIN_FILENO, TCSANOW};
    use std::mem::MaybeUninit;

    use crate::PromptError;

    fn set_stdin_echo(echo: bool) -> Result<(), PromptError> {
        let mut tty = MaybeUninit::<termios>::uninit();
        unsafe {
            if tcgetattr(STDIN_FILENO, tty.as_mut_ptr()) != 0 {
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
            if tcsetattr(STDIN_FILENO, TCSANOW, tty_ptr) != 0 {
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

    /// Read a password from STDIN (excluding newline)
    pub fn read_password_stdin() -> Result<String, PromptError> {
        let mut pass = String::new();

        let is_tty = unsafe { libc::isatty(STDIN_FILENO) == 1 };

        if is_tty {
            // Disable terminal echo
            set_stdin_echo(false)?;
        }

        let stdin = std::io::stdin();
        match stdin.read_line(&mut pass) {
            Ok(_) => {}
            Err(e) => {
                if is_tty {
                    set_stdin_echo(true)?;
                }
                return Err(PromptError::IOError(e));
            }
        };

        if is_tty {
            // Re-enable terminal echo
            set_stdin_echo(true)?;
        }

        pass = pass.trim().to_string();

        Ok(pass)
    }

    /// Write the prompt to the tty and read input from the tty
    /// Returns the String input (excluding newline)
    pub fn read_password_tty(prompt: &str) -> Result<String, PromptError> {
        unimplemented!();
    }
}
