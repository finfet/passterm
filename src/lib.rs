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
    use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::GetFileType;
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, CONSOLE_MODE, ENABLE_ECHO_INPUT,
        STD_INPUT_HANDLE,
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

        let handle = unsafe {
            let handle = GetStdHandle(STD_INPUT_HANDLE);
            if handle == INVALID_HANDLE_VALUE {
                let err = std::io::Error::last_os_error();
                return Err(PromptError::IOError(err));
            }

            handle
        };

        let console = unsafe {
            // FILE_TYPE_CHAR is 0x0002 which is a console
            // NOTE: In mysys2 terminals like git bash on windows
            // the file type comes back as FILE_TYPE_PIPE 0x03.
            // This means that we can't tell if we're in a pipe or a console
            // on msys2 terminals, so echo won't be disabled at all.
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

    /// Read a password from STDIN. Does not include the newline.
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
}
