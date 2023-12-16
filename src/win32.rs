#![allow(non_snake_case, dead_code)]

use std::ffi::c_void;

pub type HANDLE = isize;
pub type PCSTR = *const u8;
pub type BOOL = i32;

pub const FALSE: BOOL = 0i32;
pub const TRUE: BOOL = 1i32;
pub const OPEN_EXISTING: u32 = 3;
pub const GENERIC_READ: u32 = 0x80000000;
pub const GENERIC_WRITE: u32 = 0x40000000;
pub const INVALID_HANDLE_VALUE: HANDLE = -1isize;
pub const ENABLE_ECHO_INPUT: u32 = 4;
pub const STD_ERROR_HANDLE: u32 = 0xfffffff4;
pub const STD_INPUT_HANDLE: u32 = 0xfffffff6;
pub const STD_OUTPUT_HANDLE: u32 = 0xfffffff5;
pub const FILE_TYPE_CHAR: u32 = 2u32;

#[link(name = "kernel32", kind = "raw-dylib")]
extern "system" {
    pub fn CloseHandle(hobject: HANDLE) -> BOOL;
    pub fn CreateFileA(lpfilename: PCSTR, dwdesiredaccess: u32, dwsharemode: u32, lpsecurityattributes: *const c_void, dwcreationdisposition: u32, dwflagsandattributes: u32, htemplatefile: HANDLE) -> HANDLE;
    pub fn GetFileType(hfile: HANDLE) -> u32;
    pub fn GetConsoleMode(hconsolehandle: HANDLE, lpmode: *mut u32) -> BOOL;
    pub fn GetStdHandle(nstdhandle: u32) -> HANDLE;
    pub fn ReadConsoleW(hconsoleinput: HANDLE, lpbuffer: *mut c_void, nnumberofcharstoread: u32, lpnumberofcharsread: *mut u32, pinputcontrol: *const c_void) -> BOOL;
    pub fn SetConsoleMode(hconsolehandle: HANDLE, dwmode: u32) -> BOOL;
    pub fn WriteConsoleW(hconsoleoutput: HANDLE, lpbuffer: *const c_void, nnumberofcharstowrite: u32, lpnumberofcharswritten: *mut u32, lpreserved: *const c_void) -> BOOL;
}
