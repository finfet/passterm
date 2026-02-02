// Copyright 2021-2026 Kyle Schreiber
// SPDX-License-Identifier: BSD-3-Clause

#![allow(non_snake_case, dead_code)]
#![allow(clippy::upper_case_acronyms)]

use std::ffi::c_void;
use std::os::windows::raw::HANDLE;

pub type BOOL = i32;

pub const FALSE: BOOL = 0i32;
pub const TRUE: BOOL = 1i32;
pub const INVALID_HANDLE_VALUE: HANDLE = !0 as HANDLE;
pub const ENABLE_ECHO_INPUT: u32 = 4;
pub const ENABLE_LINE_INPUT: u32 = 2;
pub const ENABLE_PROCESSED_INPUT: u32 = 1;
pub const STD_ERROR_HANDLE: u32 = 0xfffffff4;
pub const STD_INPUT_HANDLE: u32 = 0xfffffff6;
pub const STD_OUTPUT_HANDLE: u32 = 0xfffffff5;
pub const FILE_TYPE_CHAR: u32 = 2u32;

windows_link::link!("kernel32.dll" "system" fn GetFileType(hfile: HANDLE) -> u32);
windows_link::link!("kernel32.dll" "system" fn GetConsoleMode(hconsolehandle: HANDLE, lpmode: *mut u32) -> BOOL);
windows_link::link!("kernel32.dll" "system" fn GetStdHandle(nstdhandle: u32) -> HANDLE);
windows_link::link!("kernel32.dll" "system" fn ReadConsoleW(
    hconsoleinput: HANDLE,
    lpbuffer: *mut c_void,
    nnumberofcharstoread: u32,
    lpnumberofcharsread: *mut u32,
    pinputcontrol: *const c_void,
) -> BOOL);
windows_link::link!("kernel32.dll" "system" fn SetConsoleMode(hconsolehandle: HANDLE, dwmode: u32) -> BOOL);
windows_link::link!("kernel32.dll" "system" fn WriteConsoleW(
    hconsoleoutput: HANDLE,
    lpbuffer: *const c_void,
    nnumberofcharstowrite: u32,
    lpnumberofcharswritten: *mut u32,
    lpreserved: *const c_void,
) -> BOOL);
