use std::error::Error;

#[cfg(target_family = "windows")]
pub use crate::windows::read_password;

#[cfg(target_family = "unix")]
pub use crate::unix::read_password;

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

    fn set_stdin_echo(echo: bool, handle: HANDLE) -> Result<(), std::io::Error> {
        let mut mode: u32 = 0;
        unsafe {
            let mode_ptr: *mut u32 = &mut mode;
            if GetConsoleMode(handle, mode_ptr as *mut CONSOLE_MODE) == BOOL::from(false) {
                return Err(std::io::Error::last_os_error());
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
                return Err(std::io::Error::last_os_error());
            }
        }

        Ok(())
    }

    /// Read a password from standard input. Newline not included.
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
        // Use a dedicated error for failing to re-enable echo.
        if let Err(e) = set_stdin_echo(true, handle) {
            return Err(PromptError::EnableFailed(e));
        }

        Ok(pass)
    }
}

#[cfg(target_family = "unix")]
mod unix {
    use crate::PromptError;

    pub fn read_password() -> Result<Vec<u8>, PromptError> {
        todo!()
    }
}
