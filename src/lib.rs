// Copyright 2021 Kyle Schreiber
// SPDX-License-Identifier: Apache-2.0

//! Prompt the user for a password without echoing.
//!
//! Use the [`read_password()`] function to read a line from stdin with
//! echo disabled.

use std::error::Error;

#[cfg(target_family = "windows")]
pub use crate::windows::read_password;

#[cfg(target_family = "unix")]
pub use crate::unix::read_password;

/// PromptError is returned if there is an issue getting user input from
/// STDIN or if terminal echo could not be disabled.
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
    use windows::Win32::Foundation::{BOOL, HANDLE};
    use windows::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, CONSOLE_MODE, ENABLE_ECHO_INPUT,
        STD_INPUT_HANDLE,
    };

    fn set_stdin_echo(echo: bool, handle: HANDLE) -> Result<(), PromptError> {
        let mut mode: u32 = 0;
        unsafe {
            let mode_ptr: *mut u32 = &mut mode;
            if GetConsoleMode(handle, mode_ptr as *mut CONSOLE_MODE) == BOOL::from(false) {
                return Err(PromptError::IOError(std::io::Error::last_os_error()));
            }
        }

        let mut mode = CONSOLE_MODE::from(mode);

        if !echo {
            mode &= !ENABLE_ECHO_INPUT;
        } else {
            mode |= ENABLE_ECHO_INPUT;
        }

        unsafe {
            if SetConsoleMode(handle, mode) == BOOL::from(false) {
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

    /// Read a password from  STDIN. Does not include the newline.
    pub fn read_password() -> Result<String, PromptError> {
        // The rust docs for std::io::Stdin note that windows does not
        // support non UTF-8 byte sequences.
        let mut pass = String::new();

        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };

        // Disable terminal echo.
        set_stdin_echo(false, handle)?;

        let stdin = std::io::stdin();
        match stdin.read_line(&mut pass) {
            Ok(_) => {}
            Err(e) => {
                set_stdin_echo(true, handle)?;
                return Err(PromptError::IOError(e));
            }
        };

        pass = pass.trim().to_string();

        // Re-enable termianal echo.
        set_stdin_echo(true, handle)?;

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
            if tcsetattr(STDIN_FILENO, TCSANOW, &mut tty as *mut _) != 0 {
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

    /// Read a password from  STDIN. Does not include the newline.
    pub fn read_password() -> Result<String, PromptError> {
        let mut pass = String::new();

        // Disable terminal echo
        set_stdin_echo(false)?;

        let stdin = std::io::stdin();
        match stdin.read_line(&mut pass) {
            Ok(_) => {}
            Err(e) => {
                set_stdin_echo(true)?;
                return Err(PromptError::IOError(e));
            }
        };

        // Re-enable terminal echo
        set_stdin_echo(true)?;

        pass = pass.trim().to_string();

        Ok(pass)
    }
}
