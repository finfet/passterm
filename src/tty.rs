// Copyright 2021-2023 Kyle Schreiber
// SPDX-License-Identifier: BSD-3-Clause

/// Stream represents the Stdin, Stdout, and Stderr streams.
#[derive(Clone, Copy, PartialEq)]
pub enum Stream {
    Stdin,
    Stdout,
    Stderr,
}

#[cfg(target_family = "windows")]
pub use crate::tty::windows::isatty;

#[cfg(target_family = "unix")]
pub use crate::tty::unix::isatty;

#[cfg(target_family = "windows")]
mod windows {
    use crate::tty::Stream;
    use crate::win32::{GetFileType, GetStdHandle};
    use crate::win32::{
        INVALID_HANDLE_VALUE, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };

    use std::os::windows::raw::HANDLE;

    /// Returns true if the given stream is a tty.
    #[allow(clippy::let_and_return)]
    pub fn isatty(stream: Stream) -> bool {
        let handle = unsafe {
            match stream {
                Stream::Stdin => match get_handle(STD_INPUT_HANDLE) {
                    Ok(h) => h,
                    Err(_) => return false,
                },
                Stream::Stdout => match get_handle(STD_OUTPUT_HANDLE) {
                    Ok(h) => h,
                    Err(_) => return false,
                },
                Stream::Stderr => match get_handle(STD_ERROR_HANDLE) {
                    Ok(h) => h,
                    Err(_) => return false,
                },
            }
        };

        let is_atty = unsafe {
            // Consoles will show as FILE_TYPE_CHAR (0x02)
            GetFileType(handle) == crate::win32::FILE_TYPE_CHAR
        };

        is_atty
    }

    unsafe fn get_handle(input_handle: u32) -> Result<HANDLE, ()> {
        let handle = GetStdHandle(input_handle);
        if handle == INVALID_HANDLE_VALUE {
            return Err(());
        }

        Ok(handle)
    }
}

#[cfg(target_family = "unix")]
mod unix {
    use crate::tty::Stream;
    use libc::{STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO};

    /// Returns true if the given stream is a tty.
    #[allow(clippy::let_and_return)]
    pub fn isatty(stream: Stream) -> bool {
        let is_atty = unsafe {
            match stream {
                Stream::Stdin => libc::isatty(STDIN_FILENO) == 1,
                Stream::Stdout => libc::isatty(STDOUT_FILENO) == 1,
                Stream::Stderr => libc::isatty(STDERR_FILENO) == 1,
            }
        };

        is_atty
    }
}
