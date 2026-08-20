//! voipcli — control the RV6699 VoIP subsystem from a root shell.
//!
//! Two independent channels, and no stock binary is patched:
//!
//! 1) CLI channel — AF_UNIX **SOCK_DGRAM** /var/voice/voip_cli.sock. vgw_app read()s a
//!    fixed 136-byte (0x88) message and dispatches on cmd_type:
//!        struct { u32 magic = 0x33229922; u32 cmd_type; u8 data[128]; }   (big-endian)
//!    cmd_type 0x12 = "run CLI command". Output is NOT returned on the socket — cli_print
//!    writes it to /dev/console + /dev/pts/0..3 (capture from a pty: ssh -tt).
//!
//! 2) Endpoint channel — /dev/bcmendpoint0 ioctl, the same path vgw_app uses for a REAL
//!    ring and CallerID (dspif_ch_ring_callerid). Reversed from vrgEndptSignal @0x4e2fb0:
//!        ioctl(fd, 0xc024d105, &SignalParm)
//!        SignalParm { size=0x24, endpt_state*, cnx_id, signal, value, status, dur, per, rep }
//!        signal 0x0F = ringing   (value 1 = on, 0 = off)
//!        signal 0x3B = caller-id (value = ptr to "MM/DD/HH/MM,  " + number, 0x52 bytes)
//!    `endpt_state` is a 12-byte object the driver fills when the endpoint is created. We do
//!    not create our own (that would fight vgw_app) — we read the live one out of vgw_app's
//!    memory: its pid is stored as 4 raw bytes in /var/voice/vgw.lock, and the endptObjState
//!    array pointer sits at the fixed address 0x0053ac64 (vgw_app is non-PIE); the per-channel
//!    entry is base + ch*12.
//!
//! Usage:
//!   voipcli "rtp_dump 0 rtp both 1000"   — run any vgw CLI command (default path)
//!   voipcli ring    <ch>                 — REAL ring on the FXS line
//!   voipcli ringoff <ch>                 — stop ringing
//!   voipcli cid     <ch> <number>        — ring + CallerID (number + date reach the phone)

#![no_std]
#![no_main]

use core::ffi::{c_char, c_int, c_long, c_void};

unsafe extern "C" {
    fn socket(domain: c_int, ty: c_int, proto: c_int) -> c_int;
    fn connect(fd: c_int, addr: *const c_void, len: u32) -> c_int;
    fn open(path: *const c_char, flags: c_int) -> c_int;
    fn read(fd: c_int, buf: *mut c_void, n: usize) -> isize;
    fn write(fd: c_int, buf: *const c_void, n: usize) -> isize;
    fn lseek(fd: c_int, off: c_long, whence: c_int) -> c_long;
    fn ioctl(fd: c_int, req: c_long, arg: *mut c_void) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn strlen(s: *const c_char) -> usize;
    fn time(t: *mut c_long) -> c_long;
    fn localtime(t: *const c_long) -> *const c_int;
    fn exit(code: c_int) -> !;
}

// ---- CLI socket channel ----
const AF_UNIX: c_int = 1;
const SOCK_DGRAM: c_int = 1; // MIPS: DGRAM=1, STREAM=2 (swapped vs x86)
const SOCK_PATH: &[u8] = b"/var/voice/voip_cli.sock";
const MAGIC: u32 = 0x3322_9922;
const CMD_RUN_CLI: u32 = 0x12;

// ---- endpoint ioctl channel ----
const DEV_ENDPOINT: &[u8] = b"/dev/bcmendpoint0\0";
const VGW_LOCK: &[u8] = b"/var/voice/vgw.lock\0";
const ENDPT_OBJ_STATE_PTR: c_long = 0x0053_ac64; // holds base of endptObjState[] in vgw_app
const ENDPT_STATE_SIZE: usize = 12; // bytes per endpoint entry
const IOCTL_ENDPT_SIGNAL: c_long = 0xc024_d105u32 as i32 as c_long;
const EPSIG_RINGING: u32 = 0x0F;
const EPSIG_CALLERID: u32 = 0x3B;
const O_RDONLY: c_int = 0;
const O_RDWR: c_int = 2;

#[repr(C)]
struct SockaddrUn {
    sun_family: u16,
    sun_path: [u8; 108],
}

/// Layout of the ioctl argument, exactly as vrgEndptSignal builds it.
#[repr(C)]
struct SignalParm {
    size: u32, // 0x24
    endpt_state: u32,
    cnx_id: u32,
    signal: u32,
    value: u32,
    status: u32,
    duration: u32,
    period: u32,
    repetition: u32,
}

#[panic_handler]
fn p(_: &core::panic::PanicInfo) -> ! {
    unsafe { exit(3) }
}

fn say(msg: &[u8]) {
    unsafe { write(1, msg.as_ptr() as *const c_void, msg.len()) };
}

fn arg(argv: *const *const c_char, i: isize) -> &'static [u8] {
    unsafe {
        let p = *argv.offset(i);
        if p.is_null() {
            return b"";
        }
        core::slice::from_raw_parts(p as *const u8, strlen(p))
    }
}

fn atoi(s: &[u8]) -> u32 {
    let mut v: u32 = 0;
    for &c in s {
        if c < b'0' || c > b'9' {
            break;
        }
        v = v * 10 + (c - b'0') as u32;
    }
    v
}

/// two-digit decimal, zero padded
fn two(buf: &mut [u8], at: usize, v: i32) {
    let v = if v < 0 { 0u32 } else { v as u32 } % 100;
    buf[at] = b'0' + (v / 10) as u8;
    buf[at + 1] = b'0' + (v % 10) as u8;
}

/// Read the live 12-byte ENDPT_STATE for `ch` out of the running vgw_app.
fn fetch_endpt_state(ch: u32, out: &mut [u8; ENDPT_STATE_SIZE]) -> bool {
    unsafe {
        // 1) pid: vgw_app writes getpid() as 4 raw bytes into its lock file
        let lf = open(VGW_LOCK.as_ptr() as *const c_char, O_RDONLY);
        if lf < 0 {
            say(b"voipcli: cannot open /var/voice/vgw.lock (is VoIP running?)\n");
            return false;
        }
        let mut pidb = [0u8; 4];
        let n = read(lf, pidb.as_mut_ptr() as *mut c_void, 4);
        close(lf);
        if n != 4 {
            say(b"voipcli: short read on vgw.lock\n");
            return false;
        }
        let pid = u32::from_be_bytes(pidb);

        // 2) build "/proc/<pid>/mem"
        let mut path = [0u8; 32];
        let head = b"/proc/";
        path[..head.len()].copy_from_slice(head);
        let mut i = head.len();
        let mut digits = [0u8; 10];
        let mut d = 0usize;
        let mut v = pid;
        if v == 0 {
            digits[0] = b'0';
            d = 1;
        }
        while v > 0 {
            digits[d] = b'0' + (v % 10) as u8;
            v /= 10;
            d += 1;
        }
        while d > 0 {
            d -= 1;
            path[i] = digits[d];
            i += 1;
        }
        let tail = b"/mem\0";
        path[i..i + tail.len()].copy_from_slice(tail);

        let mf = open(path.as_ptr() as *const c_char, O_RDONLY);
        if mf < 0 {
            say(b"voipcli: cannot open /proc/<vgw>/mem (need root)\n");
            return false;
        }
        // 3) base pointer of endptObjState[]
        if lseek(mf, ENDPT_OBJ_STATE_PTR, 0) < 0 {
            close(mf);
            return false;
        }
        let mut baseb = [0u8; 4];
        if read(mf, baseb.as_mut_ptr() as *mut c_void, 4) != 4 {
            close(mf);
            say(b"voipcli: cannot read endptObjState pointer\n");
            return false;
        }
        let base = u32::from_be_bytes(baseb) as c_long;
        if base == 0 {
            close(mf);
            say(b"voipcli: endptObjState is null\n");
            return false;
        }
        // 4) the per-channel entry
        if lseek(mf, base + (ch as c_long) * (ENDPT_STATE_SIZE as c_long), 0) < 0 {
            close(mf);
            return false;
        }
        let ok =
            read(mf, out.as_mut_ptr() as *mut c_void, ENDPT_STATE_SIZE) == ENDPT_STATE_SIZE as isize;
        close(mf);
        if !ok {
            say(b"voipcli: cannot read endpoint state\n");
        }
        ok
    }
}

/// Issue one endptSignal ioctl. `value` is either a scalar or a pointer (CallerID buffer).
fn endpt_signal(state: &[u8; ENDPT_STATE_SIZE], signal: u32, value: u32) -> bool {
    unsafe {
        let fd = open(DEV_ENDPOINT.as_ptr() as *const c_char, O_RDWR);
        if fd < 0 {
            say(b"voipcli: cannot open /dev/bcmendpoint0\n");
            return false;
        }
        let mut parm = SignalParm {
            size: 0x24,
            endpt_state: state.as_ptr() as u32,
            cnx_id: 0xFFFF_FFFF,
            signal,
            value,
            status: 8,
            duration: 0xFFFF_FFFF,
            period: 0xFFFF_FFFF,
            repetition: 0xFFFF_FFFF,
        };
        let rc = ioctl(fd, IOCTL_ENDPT_SIGNAL, &mut parm as *mut SignalParm as *mut c_void);
        close(fd);
        if rc != 0 {
            say(b"voipcli: endpoint ioctl failed\n");
            return false;
        }
        if parm.status != 0 {
            say(b"voipcli: endpoint returned non-OK status\n");
        }
        true
    }
}

/// Build the CallerID payload: "MM/DD/HH/MM,  " (14 bytes, from localtime) + number.
fn build_cid(number: &[u8], buf: &mut [u8; 0x52]) {
    unsafe {
        let t = time(core::ptr::null_mut());
        let tm = localtime(&t as *const c_long);
        let (mon, mday, hour, min) = if tm.is_null() {
            (1, 1, 0, 0)
        } else {
            // struct tm: sec@0, min@4, hour@8, mday@0xc, mon@0x10
            (
                *tm.offset(4) + 1,
                *tm.offset(3),
                *tm.offset(2),
                *tm.offset(1),
            )
        };
        two(buf, 0, mon);
        buf[2] = b'/';
        two(buf, 3, mday);
        buf[5] = b'/';
        two(buf, 6, hour);
        buf[8] = b'/';
        two(buf, 9, min);
        buf[11] = b',';
        buf[12] = b' ';
        buf[13] = b' ';
        let n = if number.len() > 0x44 { 0x44 } else { number.len() };
        buf[14..14 + n].copy_from_slice(&number[..n]);
    }
}

/// Legacy path: hand a command line to vgw's CLI over the CGI socket.
fn send_cli(cmd: &[u8]) -> c_int {
    let mut msg = [0u8; 136];
    msg[0..4].copy_from_slice(&MAGIC.to_be_bytes());
    msg[4..8].copy_from_slice(&CMD_RUN_CLI.to_be_bytes());
    let n = if cmd.len() > 127 { 127 } else { cmd.len() };
    msg[8..8 + n].copy_from_slice(&cmd[..n]);

    unsafe {
        let fd = socket(AF_UNIX, SOCK_DGRAM, 0);
        if fd < 0 {
            return 1;
        }
        let mut addr = SockaddrUn {
            sun_family: AF_UNIX as u16,
            sun_path: [0u8; 108],
        };
        addr.sun_path[..SOCK_PATH.len()].copy_from_slice(SOCK_PATH);
        let len = core::mem::size_of::<SockaddrUn>() as u32;
        if connect(fd, &addr as *const SockaddrUn as *const c_void, len) < 0 {
            return 2;
        }
        write(fd, msg.as_ptr() as *const c_void, 136);
        close(fd);
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: c_int, argv: *const *const c_char) -> c_int {
    if argc < 2 {
        say(b"usage:\n  voipcli \"<vgw cli command>\"\n  voipcli ring <ch>\n  voipcli ringoff <ch>\n  voipcli cid <ch> <number>\n");
        return 1;
    }
    let a1 = arg(argv, 1);

    // --- endpoint subcommands (real ring / caller-id) ---
    if a1 == b"ring" || a1 == b"ringoff" || a1 == b"cid" {
        let ch = if argc >= 3 { atoi(arg(argv, 2)) } else { 0 };
        let mut state = [0u8; ENDPT_STATE_SIZE];
        if !fetch_endpt_state(ch, &mut state) {
            return 4;
        }
        if a1 == b"ringoff" {
            return if endpt_signal(&state, EPSIG_RINGING, 0) {
                0
            } else {
                5
            };
        }
        // ring first, then (for `cid`) the caller-id frame — same order as dspif_ch_ring_callerid
        if !endpt_signal(&state, EPSIG_RINGING, 1) {
            return 5;
        }
        if a1 == b"cid" {
            if argc < 4 {
                say(b"voipcli: cid needs a number\n");
                return 1;
            }
            let mut cid = [0u8; 0x52];
            build_cid(arg(argv, 3), &mut cid);
            if !endpt_signal(&state, EPSIG_CALLERID, cid.as_ptr() as u32) {
                return 6;
            }
        }
        return 0;
    }

    // --- default: pass the string through to the vgw CLI ---
    send_cli(a1)
}
