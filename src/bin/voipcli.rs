//! voipcli — sends a CLI command to vgw_app's voice CGI socket (/var/voice/voip_cli.sock).
//!
//! Protocol (reverse-engineered): the socket is AF_UNIX **SOCK_DGRAM** (MIPS type=1).
//! vgw read()s a fixed 136-byte (0x88) message and dispatches on cmd_type:
//!     struct { u32 magic = 0x33229922; u32 cmd_type; u8 data[128]; }  (big-endian)
//! cmd_type 0x12 = "run CLI command" (data = the command line, e.g. "rtp_dump 0 rtp both 1000").
//! The command output is NOT returned on the socket — vgw's cli_print writes it to
//! /dev/console + /dev/pts/0..3. Capture it from a pty (ssh -tt ... > dump.txt).
//!
//!   voipcli "rtp_dump 0 rtp both 1000"

#![no_std]
#![no_main]

use core::ffi::{c_char, c_int, c_void};

unsafe extern "C" {
    fn socket(domain: c_int, ty: c_int, proto: c_int) -> c_int;
    fn connect(fd: c_int, addr: *const c_void, len: u32) -> c_int;
    fn write(fd: c_int, buf: *const c_void, n: usize) -> isize;
    fn close(fd: c_int) -> c_int;
    fn strlen(s: *const c_char) -> usize;
    fn exit(code: c_int) -> !;
}

const AF_UNIX: c_int = 1;
const SOCK_DGRAM: c_int = 1; // MIPS: DGRAM=1, STREAM=2 (swapped vs x86)
const SOCK_PATH: &[u8] = b"/var/voice/voip_cli.sock";
const MAGIC: u32 = 0x3322_9922;
const CMD_RUN_CLI: u32 = 0x12;

#[repr(C)]
struct SockaddrUn {
    sun_family: u16,
    sun_path: [u8; 108],
}

#[panic_handler]
fn p(_: &core::panic::PanicInfo) -> ! {
    unsafe { exit(3) }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: c_int, argv: *const *const c_char) -> c_int {
    // build the 136-byte CGI message
    let mut msg = [0u8; 136];
    msg[0..4].copy_from_slice(&MAGIC.to_be_bytes());
    msg[4..8].copy_from_slice(&CMD_RUN_CLI.to_be_bytes());
    if argc >= 2 {
        let a = unsafe { *argv.add(1) };
        let l = unsafe { strlen(a) };
        let s = unsafe { core::slice::from_raw_parts(a as *const u8, l) };
        let n = if l > 127 { 127 } else { l };
        msg[8..8 + n].copy_from_slice(&s[..n]);
    }

    let fd = unsafe { socket(AF_UNIX, SOCK_DGRAM, 0) };
    if fd < 0 {
        return 1;
    }
    let mut addr = SockaddrUn {
        sun_family: AF_UNIX as u16,
        sun_path: [0u8; 108],
    };
    addr.sun_path[..SOCK_PATH.len()].copy_from_slice(SOCK_PATH);
    let len = core::mem::size_of::<SockaddrUn>() as u32;
    if unsafe { connect(fd, &addr as *const SockaddrUn as *const c_void, len) } < 0 {
        return 2;
    }
    unsafe { write(fd, msg.as_ptr() as *const c_void, 136) };
    unsafe { close(fd) };
    0
}
