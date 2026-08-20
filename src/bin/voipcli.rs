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
    fn ptrace(req: c_int, pid: c_int, addr: c_long, data: c_long) -> c_long;
    fn getenv(name: *const c_char) -> *const c_char;
    fn putenv(s: *const c_char) -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, opts: c_int) -> c_int;
    fn exit(code: c_int) -> !;
}

const PTRACE_PEEKDATA: c_int = 2;
const PTRACE_ATTACH: c_int = 16;
const PTRACE_DETACH: c_int = 17;

// ---- CLI socket channel ----
const AF_UNIX: c_int = 1;
const SOCK_DGRAM: c_int = 1; // MIPS: DGRAM=1, STREAM=2 (swapped vs x86)
const SOCK_PATH: &[u8] = b"/var/voice/voip_cli.sock";
const MAGIC: u32 = 0x3322_9922;
const CMD_RUN_CLI: u32 = 0x12;

// ---- endpoint ioctl channel ----
const DEV_ENDPOINT: &[u8] = b"/dev/bcmendpoint0\0";
const VGW_LOCK: &[u8] = b"/var/voice/vgw.lock\0";
// vgw_app is ET_EXEC (non-PIE), so the GOT slot at 0x0053ac64 already holds the final
// address of endptObjState[] at link time — read straight out of the shipped binary.
// Kept as a constant so we never have to fetch the pointer at runtime.
const ENDPT_OBJ_STATE_BASE: c_long = 0x005f_3ff0;
const ENDPT_STATE_SIZE: usize = 12; // bytes per endpoint entry
const IOCTL_ENDPT_SIGNAL: c_long = 0xc024_d105u32 as i32 as c_long;
const EPSIG_RINGING: u32 = 0x0F;
const EPSIG_RINGING_INT: u32 = 0x10; // internal-call variant used by ring_callerid_off
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

/// pid of vgw_app: it writes getpid() as 4 raw (big-endian) bytes into its lock file.
fn vgw_pid() -> c_int {
    unsafe {
        let lf = open(VGW_LOCK.as_ptr() as *const c_char, O_RDONLY);
        if lf < 0 {
            say(b"voipcli: cannot open /var/voice/vgw.lock (is VoIP running?)\n");
            return -1;
        }
        let mut pidb = [0u8; 4];
        let n = read(lf, pidb.as_mut_ptr() as *mut c_void, 4);
        close(lf);
        if n != 4 {
            say(b"voipcli: short read on vgw.lock\n");
            return -1;
        }
        u32::from_be_bytes(pidb) as c_int
    }
}

/// decimal-print a number into `buf` at `at`, returns the new position
fn put_num(buf: &mut [u8], at: usize, mut v: u32) -> usize {
    let mut digits = [0u8; 10];
    let mut d = 0usize;
    if v == 0 {
        digits[0] = b'0';
        d = 1;
    }
    while v > 0 {
        digits[d] = b'0' + (v % 10) as u8;
        v /= 10;
        d += 1;
    }
    let mut i = at;
    while d > 0 {
        d -= 1;
        buf[i] = digits[d];
        i += 1;
    }
    i
}

/// Try /proc/<pid>/mem first (cheap, no stop), fall back to ptrace PEEKDATA.
fn read_remote(pid: c_int, addr: c_long, out: &mut [u8; ENDPT_STATE_SIZE]) -> bool {
    unsafe {
        // --- path 1: /proc/<pid>/mem ---
        let mut path = [0u8; 32];
        let head = b"/proc/";
        path[..head.len()].copy_from_slice(head);
        let i = put_num(&mut path, head.len(), pid as u32);
        let tail = b"/mem\0";
        path[i..i + tail.len()].copy_from_slice(tail);

        let mf = open(path.as_ptr() as *const c_char, O_RDONLY);
        if mf >= 0 {
            if lseek(mf, addr, 0) >= 0
                && read(mf, out.as_mut_ptr() as *mut c_void, ENDPT_STATE_SIZE)
                    == ENDPT_STATE_SIZE as isize
            {
                close(mf);
                return true;
            }
            close(mf);
        }

        // --- path 2: ptrace attach + peek (old kernels refuse /proc/pid/mem reads) ---
        if ptrace(PTRACE_ATTACH, pid, 0, 0) < 0 {
            say(b"voipcli: ptrace attach to vgw_app failed\n");
            return false;
        }
        let mut st: c_int = 0;
        waitpid(pid, &mut st as *mut c_int, 0);
        let mut ok = true;
        let mut w = 0usize;
        while w < ENDPT_STATE_SIZE {
            let word = ptrace(PTRACE_PEEKDATA, pid, addr + w as c_long, 0);
            if word == -1 {
                ok = false;
                break;
            }
            let b = (word as u32).to_be_bytes();
            out[w..w + 4].copy_from_slice(&b);
            w += 4;
        }
        ptrace(PTRACE_DETACH, pid, 0, 0);
        if !ok {
            say(b"voipcli: cannot read endpoint state from vgw_app\n");
        }
        ok
    }
}

/// Read the live 12-byte ENDPT_STATE for `ch` out of the running vgw_app.
fn fetch_endpt_state(ch: u32, out: &mut [u8; ENDPT_STATE_SIZE]) -> bool {
    let pid = vgw_pid();
    if pid <= 0 {
        return false;
    }
    let addr = ENDPT_OBJ_STATE_BASE + (ch as c_long) * (ENDPT_STATE_SIZE as c_long);
    read_remote(pid, addr, out)
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
        // This firmware ships no /etc/TZ and no /etc/localtime, so uClibc's localtime()
        // silently reports UTC and the phone would log the call 3 hours early. Default to
        // Moscow unless the caller already exported a TZ of their own.
        if getenv(b"TZ ".as_ptr() as *const c_char).is_null() {
            putenv(b"TZ=MSK-3 ".as_ptr() as *const c_char);
        }
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

    // --- diagnostics: show the pid we found and the endpoint state we read ---
    if a1 == b"state" {
        let ch = if argc >= 3 { atoi(arg(argv, 2)) } else { 0 };
        let pid = vgw_pid();
        let mut line = [0u8; 64];
        let head = b"vgw pid=";
        line[..head.len()].copy_from_slice(head);
        let mut i = put_num(&mut line, head.len(), if pid > 0 { pid as u32 } else { 0 });
        line[i] = b'\n';
        i += 1;
        say(&line[..i]);
        if pid <= 0 {
            return 4;
        }
        let mut state = [0u8; ENDPT_STATE_SIZE];
        if !fetch_endpt_state(ch, &mut state) {
            return 4;
        }
        let hexd = b"0123456789abcdef";
        let mut hx = [0u8; ENDPT_STATE_SIZE * 3 + 8];
        let lbl = b"state: ";
        hx[..lbl.len()].copy_from_slice(lbl);
        let mut o = lbl.len();
        for &b in state.iter() {
            hx[o] = hexd[(b >> 4) as usize];
            hx[o + 1] = hexd[(b & 0xf) as usize];
            hx[o + 2] = b' ';
            o += 3;
        }
        hx[o] = b'\n';
        say(&hx[..o + 1]);
        return 0;
    }

    // --- endpoint subcommands (real ring / caller-id) ---
    if a1 == b"ring" || a1 == b"ringoff" || a1 == b"cid" {
        let ch = if argc >= 3 { atoi(arg(argv, 2)) } else { 0 };
        let mut state = [0u8; ENDPT_STATE_SIZE];
        if !fetch_endpt_state(ch, &mut state) {
            return 4;
        }
        if a1 == b"ringoff" {
            // dspif_ch_ring_callerid_off(): signal 0x0F (external) or 0x10 (internal), value 0.
            // Send both so a ring started either way is stopped.
            let a = endpt_signal(&state, EPSIG_RINGING, 0);
            let b = endpt_signal(&state, EPSIG_RINGING_INT, 0);
            return if a || b { 0 } else { 5 };
        }
        // Mark the channel as ringing exactly like dspif_ch_ring_callerid does...
        endpt_signal(&state, EPSIG_RINGING, 1);
        // ...then hand over the caller-id frame. In CIDMode=onhook_ring the driver runs the
        // WHOLE incoming-call sequence off this one signal (ring, pause, FSK, ring again),
        // which is why a bare 0x0F is silent while 0x3B actually rings the bell. `ring` is
        // therefore the same call with an empty number: it rings without showing a caller.
        let mut cid = [0u8; 0x52];
        let number: &[u8] = if a1 == b"cid" {
            if argc < 4 {
                say(b"voipcli: cid needs a number\n");
                return 1;
            }
            arg(argv, 3)
        } else {
            b""
        };
        build_cid(number, &mut cid);
        if !endpt_signal(&state, EPSIG_CALLERID, cid.as_ptr() as u32) {
            return 6;
        }
        return 0;
    }

    // --- default: pass the string through to the vgw CLI ---
    send_cli(a1)
}
