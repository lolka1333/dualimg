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
    fn bind(fd: c_int, addr: *const c_void, len: u32) -> c_int;
    fn sendto(fd: c_int, buf: *const c_void, n: usize, fl: c_int, a: *const c_void, al: u32) -> isize;
    fn recv(fd: c_int, buf: *mut c_void, n: usize, fl: c_int) -> isize;
    fn setsockopt(fd: c_int, lvl: c_int, opt: c_int, val: *const c_void, len: u32) -> c_int;
    fn getpid() -> c_int;
    fn usleep(us: u32) -> c_int;
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
// vgw_app keeps one 0xb80-byte record per voice channel; the fields we need sit at the
// front of it (seen in dspif_ch_send_packet_to_dsp / dspif_ch_ring_callerid).
const CHAN_TABLE_BASE: c_long = 0x0058_896c;
const CHAN_STRIDE: c_long = 0xb80;
const IOCTL_ENDPT_PACKET: c_long = 0xc01c_d10bu32 as i32 as c_long;
const RTP_PAYLOAD: usize = 160; // 20 ms of 8 kHz G.711
const RTP_HDR: usize = 12;
const IOCTL_ENDPT_SIGNAL: c_long = 0xc024_d105u32 as i32 as c_long;
const EPSIG_RINGING: u32 = 0x0F;
const EPSIG_RINGING_INT: u32 = 0x10; // internal-call variant used by ring_callerid_off
const EPSIG_CALLERID: u32 = 0x3B;
// Runtime provisioning (vrgEndptProvSet @0x4e3670). The telephony profile in
// /etc/telephonyProfiles.d/RU_profile.xml is pushed into the driver through this very
// call, so the same items can be re-set live — no read-only file to patch, no reflash.
const IOCTL_ENDPT_PROVSET: c_long = 0xc018_d11du32 as i32 as c_long;
const PROV_RING_VOLTAGE: u32 = 0x0a2b; // volts, ships at 57
const RING_VOLTAGE_MAX: u32 = 90; // SLIC ceiling; the profile enables HighVoltageRingSupport
// ---- SIP channel: vgw's own stack listens on the operator VLAN address ----
const AF_INET: c_int = 2;
const SOL_SOCKET: c_int = 0xffff; // MIPS
const SO_RCVTIMEO: c_int = 0x1006; // MIPS
const SIP_PORT: u16 = 5060;
const LOCAL_SIP_PORT: u16 = 5070;
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
fn read_remote(pid: c_int, addr: c_long, out: &mut [u8]) -> bool {
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
            let want = out.len();
            if lseek(mf, addr, 0) >= 0 && read(mf, out.as_mut_ptr() as *mut c_void, want) == want as isize {
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
        let want = out.len();
        while w < want {
            // NB: a peeked word of -1 is NOT an error here. The channel record holds
            // cnx_id = -1 whenever no call is up, so bailing on -1 would break reads in
            // exactly the state we most want to observe. ptrace signals real failures
            // through errno, and the caller sanity-checks the fields it gets back.
            let word = ptrace(PTRACE_PEEKDATA, pid, addr + w as c_long, 0);
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

/// One voice channel as vgw_app sees it, read straight out of its memory.
struct ChanInfo {
    opened: u32,
    cnx_id: i32,
    ept_idx: u32,
    state: [u8; ENDPT_STATE_SIZE],
}

/// Read a channel's live record. The endpoint object is NOT indexed by the channel
/// number but by the channel's ept_idx — getting that wrong is why a bare `ring 0`
/// stayed silent while `ring 1` happened to hit the right slot.
fn chan_info(ch: u32) -> Option<ChanInfo> {
    let pid = vgw_pid();
    if pid <= 0 {
        return None;
    }
    let mut hdr = [0u8; 16];
    if !read_remote(pid, CHAN_TABLE_BASE + (ch as c_long) * CHAN_STRIDE, &mut hdr) {
        say(b"voipcli: cannot read the channel record from vgw_app\n");
        return None;
    }
    let opened = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
    let cnx_id = i32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
    let ept_idx = u32::from_be_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]);
    let mut state = [0u8; ENDPT_STATE_SIZE];
    if ept_idx > 7
        || !read_remote(
            pid,
            ENDPT_OBJ_STATE_BASE + (ept_idx as c_long) * (ENDPT_STATE_SIZE as c_long),
            &mut state,
        )
    {
        say(b"voipcli: cannot read the endpoint state\n");
        return None;
    }
    Some(ChanInfo {
        opened,
        cnx_id,
        ept_idx,
        state,
    })
}

/// Feed one already-built RTP packet into an EXISTING connection. We never create or
/// destroy connections — vgw_app stays the owner of the call, we only hand its DSP more
/// audio, so there is no state machine to confuse.
fn send_packet(info: &ChanInfo, ch: u32, pkt: &[u8]) -> bool {
    unsafe {
        let fd = open(DEV_ENDPOINT.as_ptr() as *const c_char, O_RDWR);
        if fd < 0 {
            return false;
        }
        // EPPACKET { u32 mediaType; void *data; } — mediaType 0 = RTP (payload_type 1 - 1)
        let eppacket: [u32; 2] = [0, pkt.as_ptr() as u32];
        let mut parm: [u32; 7] = [
            0x1c,
            info.state.as_ptr() as u32,
            info.cnx_id as u32,
            eppacket.as_ptr() as u32,
            pkt.len() as u32,
            ch,
            8,
        ];
        let rc = ioctl(fd, IOCTL_ENDPT_PACKET, parm.as_mut_ptr() as *mut c_void);
        close(fd);
        rc == 0 && (parm[6] == 0 || parm[6] == 9)
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


#[repr(C)]
struct SockaddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

/// tiny append-to-buffer cursor, enough to assemble a SIP message without alloc
struct Buf {
    b: [u8; 1400],
    n: usize,
}
impl Buf {
    fn new() -> Buf {
        Buf {
            b: [0u8; 1400],
            n: 0,
        }
    }
    fn s(&mut self, x: &[u8]) {
        let room = self.b.len() - self.n;
        let k = if x.len() > room { room } else { x.len() };
        self.b[self.n..self.n + k].copy_from_slice(&x[..k]);
        self.n += k;
    }
    fn d(&mut self, v: u32) {
        let mut tmp = [0u8; 12];
        let e = put_num(&mut tmp, 0, v);
        let mut copy = [0u8; 12];
        copy[..e].copy_from_slice(&tmp[..e]);
        self.s(&copy[..e]);
    }
}

/// parse a dotted-quad into a host-order u32
fn parse_ip(s: &[u8]) -> u32 {
    let mut parts = [0u32; 4];
    let mut idx = 0usize;
    let mut cur = 0u32;
    for &c in s {
        if c >= b'0' && c <= b'9' {
            cur = cur * 10 + (c - b'0') as u32;
        } else if c == b'.' {
            if idx < 4 {
                parts[idx] = cur;
            }
            idx += 1;
            cur = 0;
        } else {
            break;
        }
    }
    if idx < 4 {
        parts[idx] = cur;
    }
    (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
}

/// Send a SIP INVITE straight at vgw's own stack. It listens on the operator-VLAN
/// address (netstat shows 10.254.55.17:5060) and the box can address itself, so the
/// request arrives as a genuine incoming call: the phone rings through the whole call
/// manager and the caller-id is journalled the way a real call is. Combined with an
/// unconditional call-forward (`vgw sip fw all 0 1 <number>`) the very same INVITE makes
/// the router place a REAL outbound call — dialling from the shell, no patched binary.
fn sip_invite(dest: &[u8], to_user: &[u8], from_user: &[u8], host: &[u8]) -> c_int {
    unsafe {
        let fd = socket(AF_INET, SOCK_DGRAM, 0);
        if fd < 0 {
            say(b"voipcli: socket failed\n");
            return 1;
        }
        // bind a fixed local port so Via/Contact are truthful
        let local = SockaddrIn {
            sin_family: AF_INET as u16,
            sin_port: LOCAL_SIP_PORT.to_be(),
            sin_addr: 0,
            sin_zero: [0u8; 8],
        };
        bind(fd, &local as *const SockaddrIn as *const c_void, 16);
        // short receive timeout so we can show whatever the stack answers
        let tv: [u32; 2] = [3, 0];
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, tv.as_ptr() as *const c_void, 8);

        let tag = (time(core::ptr::null_mut()) as u32) ^ (getpid() as u32);

        // SDP body first — its length goes into Content-Length
        let mut sdp = Buf::new();
        sdp.s(b"v=0\r\no=- 1 1 IN IP4 ");
        sdp.s(dest);
        sdp.s(b"\r\ns=-\r\nc=IN IP4 ");
        sdp.s(dest);
        sdp.s(b"\r\nt=0 0\r\nm=audio 40000 RTP/AVP 8 0\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:0 PCMU/8000\r\n");

        let mut m = Buf::new();
        m.s(b"INVITE sip:");
        m.s(to_user);
        m.s(b"@");
        m.s(host);
        m.s(b" SIP/2.0\r\nVia: SIP/2.0/UDP ");
        m.s(dest);
        m.s(b":");
        m.d(LOCAL_SIP_PORT as u32);
        m.s(b";branch=z9hG4bK");
        m.d(tag);
        m.s(b"\r\nMax-Forwards: 70\r\nFrom: <sip:");
        m.s(from_user);
        m.s(b"@");
        m.s(host);
        m.s(b">;tag=");
        m.d(tag);
        m.s(b"\r\nTo: <sip:");
        m.s(to_user);
        m.s(b"@");
        m.s(host);
        m.s(b">\r\nCall-ID: ");
        m.d(tag);
        m.s(b"@voipcli\r\nCSeq: 1 INVITE\r\nContact: <sip:");
        m.s(from_user);
        m.s(b"@");
        m.s(dest);
        m.s(b":");
        m.d(LOCAL_SIP_PORT as u32);
        m.s(b">\r\nContent-Type: application/sdp\r\nContent-Length: ");
        m.d(sdp.n as u32);
        m.s(b"\r\n\r\n");
        let head = m.n;
        let body = sdp.n;
        m.b[head..head + body].copy_from_slice(&sdp.b[..body]);
        m.n = head + body;

        let peer = SockaddrIn {
            sin_family: AF_INET as u16,
            sin_port: SIP_PORT.to_be(),
            sin_addr: parse_ip(dest).to_be(),
            sin_zero: [0u8; 8],
        };
        let sent = sendto(
            fd,
            m.b.as_ptr() as *const c_void,
            m.n,
            0,
            &peer as *const SockaddrIn as *const c_void,
            16,
        );
        if sent < 0 {
            say(b"voipcli: sendto failed\n");
            close(fd);
            return 2;
        }
        say(b"voipcli: INVITE sent, waiting for an answer...\n");
        let mut rb = [0u8; 1400];
        let got = recv(fd, rb.as_mut_ptr() as *mut c_void, 1400, 0);
        if got > 0 {
            write(1, rb.as_ptr() as *const c_void, got as usize);
            say(b"\n");
        } else {
            say(b"voipcli: no answer (the stack ignored it, or it filters by source)\n");
        }
        close(fd);
        0
    }
}

/// Set one endpoint provisioning item (4-byte integer value) on a channel.
fn prov_set(ch: u32, item: u32, value: u32) -> bool {
    unsafe {
        let fd = open(DEV_ENDPOINT.as_ptr() as *const c_char, O_RDWR);
        if fd < 0 {
            say(b"voipcli: cannot open /dev/bcmendpoint0
");
            return false;
        }
        let val: u32 = value;
        // struct: size, lineId, item, value ptr, value len, status
        let mut parm: [u32; 6] = [
            0x18,
            ch,
            item,
            &val as *const u32 as u32,
            4,
            8,
        ];
        let rc = ioctl(fd, IOCTL_ENDPT_PROVSET, parm.as_mut_ptr() as *mut c_void);
        close(fd);
        if rc != 0 {
            say(b"voipcli: provisioning ioctl failed
");
            return false;
        }
        if parm[5] != 0 {
            say(b"voipcli: endpoint rejected the value
");
            return false;
        }
        true
    }
}

/// Stream a raw G.711 file into a live call: 160 bytes (20 ms) per RTP packet.
/// Refuses unless vgw_app already has a connection up on the channel — that interlock is
/// what keeps us from ever touching its call state.
fn play_file(ch: u32, path: &[u8], pt: u32) -> c_int {
    let info = match chan_info(ch) {
        Some(i) => i,
        None => return 4,
    };
    if info.cnx_id < 0 || info.opened == 0 {
        say(b"voipcli: no active call on this channel - pick up the handset first\n");
        return 5;
    }
    play_on(&info, ch, path, pt)
}

/// Stream the file into a connection that was already looked up.
fn play_on(info: &ChanInfo, ch: u32, path: &[u8], pt: u32) -> c_int {
    unsafe {
        let fd = open(path.as_ptr() as *const c_char, O_RDONLY);
        if fd < 0 {
            say(b"voipcli: cannot open the audio file\n");
            return 6;
        }
        let mut pkt = [0u8; RTP_HDR + RTP_PAYLOAD];
        pkt[0] = 0x80;
        pkt[1] = pt as u8;
        let ssrc: u32 = 0x7601_c11a;
        pkt[8..12].copy_from_slice(&ssrc.to_be_bytes());
        let mut seq: u16 = 0;
        let mut ts: u32 = 0;
        let mut sent: u32 = 0;
        loop {
            let n = read(
                fd,
                pkt[RTP_HDR..].as_mut_ptr() as *mut c_void,
                RTP_PAYLOAD,
            );
            if n <= 0 {
                break;
            }
            // pad a short final chunk with A-law silence
            if (n as usize) < RTP_PAYLOAD {
                for b in pkt[RTP_HDR + n as usize..].iter_mut() {
                    *b = 0xd5;
                }
            }
            pkt[2..4].copy_from_slice(&seq.to_be_bytes());
            pkt[4..8].copy_from_slice(&ts.to_be_bytes());
            if !send_packet(info, ch, &pkt) {
                say(b"voipcli: the DSP refused a packet, stopping\n");
                close(fd);
                return 7;
            }
            seq = seq.wrapping_add(1);
            ts = ts.wrapping_add(RTP_PAYLOAD as u32);
            sent = sent.wrapping_add(1);
            usleep(20000); // one packet per 20 ms, or the audio runs fast
        }
        close(fd);
        say(b"voipcli: finished\n");
        let _ = sent;
        0
    }
}

/// Ring the phone, wait for it to be picked up, then speak the file into it.
///
/// Off-hook is detected by watching vgw_app's own channel record: when the handset comes
/// up its LSM opens the DSP channel (dspif_ch_open sets cnx_id = channel and opened = 1),
/// which is exactly the connection we are allowed to feed. We stop the ring, silence the
/// dial tone vgw starts playing, and stream the audio in.
fn announce(ch: u32, number: &[u8], path: &[u8]) -> c_int {
    let info = match chan_info(ch) {
        Some(i) => i,
        None => return 4,
    };
    // start ringing with the caller id
    endpt_signal(&info.state, EPSIG_RINGING, 1);
    let mut cid = [0u8; 0x52];
    build_cid(number, &mut cid);
    if !endpt_signal(&info.state, EPSIG_CALLERID, cid.as_ptr() as u32) {
        return 5;
    }
    say(b"voipcli: ringing - pick up the handset\n");

    // wait for off-hook (~40 s), polling gently so vgw is barely disturbed
    let mut live: Option<ChanInfo> = None;
    let mut tries = 0;
    while tries < 80 {
        unsafe { usleep(500_000) };
        tries += 1;
        if let Some(i) = chan_info(ch) {
            if i.opened != 0 && i.cnx_id >= 0 {
                live = Some(i);
                break;
            }
        }
    }
    let live = match live {
        Some(i) => i,
        None => {
            endpt_signal(&info.state, EPSIG_RINGING, 0);
            endpt_signal(&info.state, EPSIG_RINGING_INT, 0);
            say(b"voipcli: nobody picked up\n");
            return 6;
        }
    };

    // stop the ring and the dial tone the line manager starts on off-hook
    endpt_signal(&live.state, EPSIG_RINGING, 0);
    endpt_signal(&live.state, EPSIG_RINGING_INT, 0);
    let mut cmd = [0u8; 32];
    let head = b"dsp tone_off ";
    cmd[..head.len()].copy_from_slice(head);
    let n = put_num(&mut cmd, head.len(), ch);
    send_cli(&cmd[..n]);
    unsafe { usleep(300_000) };

    say(b"voipcli: picked up - playing\n");
    play_on(&live, ch, path, 8)
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
        let state = match chan_info(ch) {
            Some(i) => i.state,
            None => return 4,
        };
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

    // --- read-only: what vgw_app thinks the channel is doing ---
    if a1 == b"cnx" {
        let ch = if argc >= 3 { atoi(arg(argv, 2)) } else { 0 };
        let info = match chan_info(ch) {
            Some(i) => i,
            None => return 4,
        };
        let mut line = [0u8; 96];
        let mut i = 0usize;
        let l1 = b"opened=";
        line[i..i + l1.len()].copy_from_slice(l1);
        i += l1.len();
        i = put_num(&mut line, i, info.opened);
        let l2 = b" cnx_id=";
        line[i..i + l2.len()].copy_from_slice(l2);
        i += l2.len();
        if info.cnx_id < 0 {
            line[i] = b'-';
            i += 1;
            i = put_num(&mut line, i, (-info.cnx_id) as u32);
        } else {
            i = put_num(&mut line, i, info.cnx_id as u32);
        }
        let l3 = b" ept_idx=";
        line[i..i + l3.len()].copy_from_slice(l3);
        i += l3.len();
        i = put_num(&mut line, i, info.ept_idx);
        line[i] = b'\n';
        i += 1;
        say(&line[..i]);
        if info.cnx_id < 0 {
            say(b"(cnx_id -1 = no call up; audio can only be injected during a call)
");
        }
        return 0;
    }

    // --- ring, wait for pick-up, then speak ---
    if a1 == b"announce" {
        if argc < 5 {
            say(b"usage: voipcli announce <ch> <caller-number> <file.alaw>
");
            return 1;
        }
        let ch = atoi(arg(argv, 2));
        let raw = arg(argv, 4);
        let mut path = [0u8; 128];
        let n = if raw.len() > 126 { 126 } else { raw.len() };
        path[..n].copy_from_slice(&raw[..n]);
        return announce(ch, arg(argv, 3), &path);
    }

    // --- play raw G.711 into a live call ---
    if a1 == b"play" {
        if argc < 4 {
            say(b"usage: voipcli play <ch> <file.alaw> [payload-type, default 8=A-law]
");
            return 1;
        }
        let ch = atoi(arg(argv, 2));
        let pt = if argc >= 5 { atoi(arg(argv, 4)) } else { 8 };
        // path must be NUL-terminated for open()
        let raw = arg(argv, 3);
        let mut path = [0u8; 128];
        let n = if raw.len() > 126 { 126 } else { raw.len() };
        path[..n].copy_from_slice(&raw[..n]);
        return play_file(ch, &path, pt);
    }

    // --- provisioning: ring loudness and any other endpoint item, applied live ---
    if a1 == b"ringvolt" || a1 == b"prov" {
        let ch = if argc >= 3 { atoi(arg(argv, 2)) } else { 0 };
        let (item, value) = if a1 == b"ringvolt" {
            if argc < 4 {
                say(b"usage: voipcli ringvolt <ch> <volts>   (stock 57, ceiling 90)
");
                return 1;
            }
            let mut v = atoi(arg(argv, 3));
            if v > RING_VOLTAGE_MAX {
                say(b"voipcli: clamping to the 90 V SLIC ceiling
");
                v = RING_VOLTAGE_MAX;
            }
            (PROV_RING_VOLTAGE, v)
        } else {
            if argc < 5 {
                say(b"usage: voipcli prov <ch> <item> <value>   (item is decimal, e.g. 2603 = RingVoltage)
");
                return 1;
            }
            (atoi(arg(argv, 3)), atoi(arg(argv, 4)))
        };
        if !prov_set(ch, item, value) {
            return 7;
        }
        say(b"voipcli: applied
");
        return 0;
    }

    // --- SIP: hand an INVITE to vgw's own stack (real incoming call / dial via forward) ---
    if a1 == b"invite" {
        if argc < 4 {
            say(b"usage: voipcli invite <to-number> <from-number> [stack-ip] [host]\n");
            return 1;
        }
        let dest = if argc >= 5 {
            arg(argv, 4)
        } else {
            b"10.254.55.17" as &[u8]
        };
        let host = if argc >= 6 {
            arg(argv, 5)
        } else {
            b"msk.ims.mgts.ru" as &[u8]
        };
        return sip_invite(dest, arg(argv, 2), arg(argv, 3), host);
    }

    // --- endpoint subcommands (real ring / caller-id) ---
    if a1 == b"ring" || a1 == b"ringoff" || a1 == b"cid" {
        let ch = if argc >= 3 { atoi(arg(argv, 2)) } else { 0 };
        let state = match chan_info(ch) {
            Some(i) => i.state,
            None => return 4,
        };
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
