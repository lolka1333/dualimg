//! voipcli — minimal AF_UNIX client for the vgw_app voice CLI socket.
//! Connects to /var/voice/voip_cli.sock, sends argv[1] as one command line,
//! then relays the (streaming) response to stdout until the socket closes.
//!
//! Record a call (run in background, place/answer the call, then kill it):
//!   voipcli "rtp_dump 0 rtp both 1000" > /var/dump.txt &
//!   ... call ...
//!   killall voipcli      # or: kill %1
//! Then decode dump.txt -> WAV on the PC (rtp_to_wav.py).

#![no_std]
#![no_main]

use core::ffi::{c_char, c_int, c_void};

unsafe extern "C" {
    fn socket(domain: c_int, ty: c_int, proto: c_int) -> c_int;
    fn connect(fd: c_int, addr: *const c_void, len: u32) -> c_int;
    fn write(fd: c_int, buf: *const c_void, n: usize) -> isize;
    fn read(fd: c_int, buf: *mut c_void, n: usize) -> isize;
    fn close(fd: c_int) -> c_int;
    fn strlen(s: *const c_char) -> usize;
    fn exit(code: c_int) -> !;
}

const AF_UNIX: c_int = 1;
const SOCK_STREAM: c_int = 2;
const SOCK_PATH: &[u8] = b"/var/voice/voip_cli.sock";

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
    // command = argv[1] + '\n'  (defaults to "help")
    let mut cmd = [0u8; 256];
    let mut clen;
    if argc >= 2 {
        let a = unsafe { *argv.add(1) };
        let l = unsafe { strlen(a) };
        let s = unsafe { core::slice::from_raw_parts(a as *const u8, l) };
        clen = if l > 254 { 254 } else { l };
        cmd[..clen].copy_from_slice(&s[..clen]);
        cmd[clen] = b'\n';
        clen += 1;
    } else {
        cmd[..5].copy_from_slice(b"help\n");
        clen = 5;
    }

    let fd = unsafe { socket(AF_UNIX, SOCK_STREAM, 0) };
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
    unsafe { write(fd, cmd.as_ptr() as *const c_void, clen) };

    // relay socket -> stdout until EOF (kill the process to stop after the call)
    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe { read(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        if n <= 0 {
            break;
        }
        unsafe { write(1, buf.as_ptr() as *const c_void, n as usize) };
    }
    unsafe { close(fd) };
    0
}
