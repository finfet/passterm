/// Stream represents the Stdin, Stdout, and Stderr streams.
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
    use windows::Win32::Storage::FileSystem::GetFileType;
    use windows::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };

    #[allow(clippy::let_and_return)]
    /// Returns true if the given stream is a tty
    pub fn isatty(stream: Stream) -> bool {
        let handle = unsafe {
            match stream {
                Stream::Stdin => GetStdHandle(STD_INPUT_HANDLE),
                Stream::Stdout => GetStdHandle(STD_OUTPUT_HANDLE),
                Stream::Stderr => GetStdHandle(STD_ERROR_HANDLE),
            }
        };

        let is_atty = unsafe {
            // 0x02 is FILE_TYPE_CHAR which consoles show as.
            GetFileType(handle) == 0x02
        };

        is_atty
    }
}

#[cfg(target_family = "unix")]
mod unix {
    use crate::tty::Stream;
    use libc::{STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO};

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
