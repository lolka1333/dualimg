//! dualimg — from-scratch RV6699 firmware flasher ("our own dualImage_ctrl").
//!
//! no_std, links static musl (mips-linux-muslsf). Pure-Rust crypto/inflate.
//! Implements the byte-exact, reverse-engineered upgrade path:
//!   decrypt(AES-256-CBC) -> verify(sha256) -> inflate(gzip) -> per-section:
//!   pick INACTIVE bank -> bad-block pre-scan (ABORT on any) -> flash_eraseall -j
//!   -> write 128K chunks + READBACK+memcmp -> finally swap mtd9 commit byte.
//!
//! SAFETY INVARIANTS (make any bug recoverable, never a hard brick):
//!   * section-name ALLOWLIST: only "kernel_rootfs"/"rootfs_lib" — never "bootloader" (mtd12).
//!   * write the INACTIVE bank only (active bank stays bootable -> CFE auto-fallback).
//!   * swap (mtd9 commit) LAST, only after every section wrote AND read back identical.
//!   * abort on ANY bad block (never produce the OEM's silent offset-shifted image).
//!
//! Operator-gate: a write only proceeds if the owner marker /tmp/.owner_flash holds the
//! secret (md5 == OWNER_MD5). Without it (operator via cwmp/omcid) -> fake-success exit 0.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::ffi::{c_char, c_int, c_ulong, c_void};
use core::panic::PanicInfo;

use aes::Aes256;
use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use md5::{Digest, Md5};
use sha2::Sha256;

// ---- md5 of the owner flash-secret (NOT the secret). Change for production. ----
// printf '%s' 'rv6699-flash-secret' > /tmp/.owner_flash   (default below)
const OWNER_MD5: [u8; 16] = [
    0xe0, 0x36, 0x46, 0x6f, 0x2a, 0x30, 0x3c, 0xef, 0xda, 0xc9, 0x65, 0x44, 0x82, 0xd2, 0x97, 0xd4,
];
const MARKER: &str = "/tmp/.owner_flash\0";

// Expected model token at the start of the section version string (e.g.
// "RV6688v2_SERCOMM_MTS_3346"). Refuse images whose version doesn't match -> never
// flash a wrong-model image. (OEM only LOGS the version; we enforce it.)
const EXPECT_MODEL: &[u8] = b"RV6688v2";

// ===================== libc (static musl) =====================
unsafe extern "C" {
    fn open(path: *const c_char, flags: c_int, ...) -> c_int;
    fn read(fd: c_int, buf: *mut c_void, n: usize) -> isize;
    fn write(fd: c_int, buf: *const c_void, n: usize) -> isize;
    fn close(fd: c_int) -> c_int;
    // musl uses 64-bit off_t on ILP32 -> these take/return i64.
    fn lseek(fd: c_int, off: i64, whence: c_int) -> i64;
    fn ioctl(fd: c_int, req: c_ulong, arg: *mut c_void) -> c_int;
    fn system(cmd: *const c_char) -> c_int;
    fn sync();
    fn malloc(n: usize) -> *mut c_void;
    fn free(p: *mut c_void);
    fn exit(code: c_int) -> !;
}

const O_RDONLY: c_int = 0;
const O_RDWR: c_int = 2;
const SEEK_SET: c_int = 0;
const MEMGETBADBLOCK: c_ulong = 0x8008_4d0b; // arg = *loff_t(block offset); rc>0 => bad
const BLOCK: usize = 0x2_0000; // 128 KiB erase block / chunk
const STDERR: c_int = 2;

// ---- global allocator over musl malloc/free ----
struct Libc;
unsafe impl core::alloc::GlobalAlloc for Libc {
    unsafe fn alloc(&self, l: core::alloc::Layout) -> *mut u8 {
        // musl malloc gives >=16-byte alignment; sufficient for Vec<u8>/crypto state.
        unsafe { malloc(l.size()) as *mut u8 }
    }
    unsafe fn dealloc(&self, p: *mut u8, _l: core::alloc::Layout) {
        unsafe { free(p as *mut c_void) }
    }
}
#[global_allocator]
static ALLOC: Libc = Libc;

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    eprint(b"dualimg: internal panic\n");
    unsafe { exit(3) }
}

// ===================== small helpers =====================
fn eprint(s: &[u8]) {
    unsafe { write(STDERR, s.as_ptr() as *const c_void, s.len()) };
}
fn die(s: &[u8]) -> ! {
    eprint(b"dualimg: ");
    eprint(s);
    eprint(b"\n");
    unsafe { exit(1) }
}

/// Read an entire file into a Vec. NUL-terminated path required.
fn read_file(path: &[u8]) -> Option<Vec<u8>> {
    let fd = unsafe { open(path.as_ptr() as *const c_char, O_RDONLY) };
    if fd < 0 {
        return None;
    }
    let mut out = Vec::new();
    let mut tmp = vec![0u8; BLOCK];
    loop {
        let n = unsafe { read(fd, tmp.as_mut_ptr() as *mut c_void, tmp.len()) };
        if n < 0 {
            unsafe { close(fd) };
            return None;
        }
        if n == 0 {
            break;
        }
        out.extend_from_slice(&tmp[..n as usize]);
    }
    unsafe { close(fd) };
    Some(out)
}

/// atol on an ASCII-decimal field (stops at first non-digit; leading non-digits skipped).
fn atol(b: &[u8]) -> usize {
    let mut v = 0usize;
    let mut started = false;
    for &c in b {
        if c.is_ascii_digit() {
            v = v * 10 + (c - b'0') as usize;
            started = true;
        } else if started {
            break;
        }
    }
    v
}

/// Run a shell command (NUL-terminated). Returns the raw system() result.
fn shell(cmd: &[u8]) -> c_int {
    unsafe { system(cmd.as_ptr() as *const c_char) }
}

// ===================== owner gate =====================
fn owner_authorized() -> bool {
    let Some(data) = read_file(MARKER.as_bytes()) else {
        return false;
    };
    // marker holds the raw secret; compare md5(secret) to the baked digest.
    let d = Md5::digest(&data);
    d.as_slice() == &OWNER_MD5[..]
}

// ===================== crypto / image =====================
/// AES key = MD5(hdr[0x60..0x80] || hdr[0x20..0x40]) || MD5(hdr[0x80..0xA0] || hdr[0x20..0x40]).
fn derive_key(hdr: &[u8]) -> [u8; 32] {
    let salt = &hdr[0x20..0x40];
    let mut h1 = Md5::new();
    h1.update(&hdr[0x60..0x80]);
    h1.update(salt);
    let d1 = h1.finalize();
    let mut h2 = Md5::new();
    h2.update(&hdr[0x80..0xA0]);
    h2.update(salt);
    let d2 = h2.finalize();
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(&d1);
    key[16..].copy_from_slice(&d2);
    key
}

/// Decrypt the .img in memory -> plaintext (PKCS#7 stripped). IV = hdr[0x40..0x50].
fn decrypt(img: &[u8]) -> Vec<u8> {
    if img.len() < 0xA0 {
        die(b"image too small");
    }
    let key = derive_key(&img[..0xA0]);
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&img[0x40..0x50]);
    let ct = &img[0xA0..];
    let n = ct.len() / 16 * 16;
    let mut buf = ct[..n].to_vec();
    type Dec = cbc::Decryptor<Aes256>;
    let dec = Dec::new((&key).into(), (&iv).into());
    let pt = dec
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .unwrap_or_else(|_| die(b"AES/PKCS7 decrypt failed"));
    // OEM ftruncate(atol(hdr[0x80..0xA0])): the unpadded length MUST equal the header field.
    let want = atol(&img[0x80..0xA0]);
    if pt.len() != want {
        die(b"plaintext length != header length field");
    }
    pt.to_vec()
}

/// verify_image: tag "42463900.." + sha256(pt[0xA0..]) == pt[0x80..0xA0].
fn verify(pt: &[u8]) {
    if pt.len() < 0xA0 {
        die(b"plaintext too small");
    }
    let tag = b"42463900000000000000000000000000";
    if &pt[0x08..0x28] != tag {
        die(b"tag mismatch (not a sercomm image)");
    }
    let want = &pt[0x80..0xA0];
    let got = Sha256::digest(&pt[0xA0..]);
    if got.as_slice() != want {
        die(b"digest check FAIL");
    }
    eprint(b"digest check OK.\n");
}

/// Strip the gzip framing and raw-inflate the deflate stream.
fn gunzip(pt: &[u8]) -> Vec<u8> {
    // gzip stream is at 0xA0 (after outer80 + 32-byte digest). Anchor the search there so a stray
    // 1f8b08 inside the header/digest can't be mistaken for the stream start.
    if pt.len() < 0xA0 {
        die(b"plaintext too small for gzip");
    }
    let rel = pt[0xA0..]
        .windows(3)
        .position(|w| w == [0x1f, 0x8b, 0x08])
        .unwrap_or_else(|| die(b"no gzip stream at/after 0xA0"));
    let g = &pt[0xA0 + rel..];
    if g.len() < 10 {
        die(b"truncated gzip");
    }
    let flg = g[3];
    let mut off = 10usize;
    if flg & 0x04 != 0 {
        // FEXTRA
        let xlen = g[off] as usize | (g[off + 1] as usize) << 8;
        off += 2 + xlen;
    }
    if flg & 0x08 != 0 {
        // FNAME
        while g[off] != 0 {
            off += 1;
        }
        off += 1;
    }
    if flg & 0x10 != 0 {
        // FCOMMENT
        while g[off] != 0 {
            off += 1;
        }
        off += 1;
    }
    if flg & 0x02 != 0 {
        // FHCRC
        off += 2;
    }
    miniz_oxide::inflate::decompress_to_vec(&g[off..]).unwrap_or_else(|_| die(b"inflate failed"))
}

// ===================== bank state (/proc/FW_INFO) =====================
/// run flag = atoi(/proc/FW_INFO/isUsed); MUST be 1 or 2 (else refuse, never misroute).
fn run_flag() -> u32 {
    let d = read_file(b"/proc/FW_INFO/isUsed\0").unwrap_or_else(|| die(b"no /proc/FW_INFO/isUsed"));
    match atol(&d) {
        1 => 1,
        2 => 2,
        _ => die(b"isUsed not in {1,2} -- refusing"),
    }
}

/// Inactive-bank devices for the run flag. isUsed==2 -> bank A (mtd5/6), else bank B (mtd7/8).
fn inactive_rootfs(rf: u32) -> &'static [u8] {
    if rf == 2 { b"/dev/mtd5\0" } else { b"/dev/mtd7\0" }
}
fn inactive_lib(rf: u32) -> &'static [u8] {
    if rf == 2 { b"/dev/mtd6\0" } else { b"/dev/mtd8\0" }
}
fn erase_dev(rf: u32, lib: bool) -> &'static [u8] {
    // command strings for flash_eraseall -j (busybox = OS tool, writes the JFFS2 clean marker).
    match (rf == 2, lib) {
        (true, false) => b"/usr/sbin/flash_eraseall -j /dev/mtd5\0",
        (false, false) => b"/usr/sbin/flash_eraseall -j /dev/mtd7\0",
        (true, true) => b"/usr/sbin/flash_eraseall -j /dev/mtd6\0",
        (false, true) => b"/usr/sbin/flash_eraseall -j /dev/mtd8\0",
    }
}

// ===================== NAND write =====================
/// Pre-scan: ABORT if any erase block in [0,len) is factory/runtime bad
/// (OEM silently skips+shifts; we refuse rather than produce a shifted image).
fn assert_no_bad_blocks(fd: c_int, len: usize) {
    let mut off = 0u64;
    while (off as usize) < len {
        let mut arg = off; // loff_t
        let rc = unsafe { ioctl(fd, MEMGETBADBLOCK, &mut arg as *mut u64 as *mut c_void) };
        if rc > 0 {
            die(b"bad block in target bank -- aborting (clean bank required)");
        }
        off += BLOCK as u64;
    }
}

/// Pre-scan the target device for bad blocks BEFORE erasing it (so the abort happens
/// before we touch the bank at all). Opens read-only, scans, closes.
fn prescan_bad(dev: &[u8], len: usize) {
    let fd = unsafe { open(dev.as_ptr() as *const c_char, O_RDONLY) };
    if fd < 0 {
        die(b"open mtd for bad-block scan failed");
    }
    assert_no_bad_blocks(fd, len);
    unsafe { close(fd) };
}

/// Write `data` to an mtd char device sequentially in 128K chunks, then read EVERYTHING
/// back and memcmp. Returns only on full success; dies on any short write / mismatch.
/// (Bad blocks are already ruled out by prescan_bad() before the erase.)
fn write_and_verify(dev: &[u8], data: &[u8]) {
    let fd = unsafe { open(dev.as_ptr() as *const c_char, O_RDWR) };
    if fd < 0 {
        die(b"open mtd for write failed");
    }

    let mut off = 0usize;
    while off < data.len() {
        let end = core::cmp::min(off + BLOCK, data.len());
        let chunk = &data[off..end];
        let w = unsafe { write(fd, chunk.as_ptr() as *const c_void, chunk.len()) };
        if w != chunk.len() as isize {
            unsafe { close(fd) };
            die(b"short write to mtd");
        }
        off = end;
    }

    // independent full readback (the OEM's write_mtd swallows write_blk's status; we don't).
    if unsafe { lseek(fd, 0, SEEK_SET) } != 0 {
        unsafe { close(fd) };
        die(b"lseek for readback failed");
    }
    let mut back = vec![0u8; BLOCK];
    let mut off = 0usize;
    while off < data.len() {
        let end = core::cmp::min(off + BLOCK, data.len());
        let want = &data[off..end];
        let r = unsafe { read(fd, back.as_mut_ptr() as *mut c_void, want.len()) };
        if r != want.len() as isize || &back[..want.len()] != want {
            unsafe { close(fd) };
            die(b"readback mismatch -- bank NOT trustworthy");
        }
        off = end;
    }
    unsafe { close(fd) };
}

// ===================== mtd9 commit (the swap) =====================
/// Flip the boot bank: read mtd9 block, set COMMIT byte @offset 8 = '0'+(3-run_flag),
/// erase + write the block back. ACTIVE byte @7 and version slots are preserved.
fn swap_commit(rf: u32) {
    let target = 3 - rf; // 1<->2 ; the bank we just wrote
    let fd = unsafe { open(b"/dev/mtd9\0".as_ptr() as *const c_char, O_RDWR) };
    if fd < 0 {
        die(b"open mtd9 failed");
    }
    let mut blk = vec![0u8; BLOCK];
    let r = unsafe { read(fd, blk.as_mut_ptr() as *mut c_void, BLOCK) };
    if r != BLOCK as isize {
        unsafe { close(fd) };
        die(b"read mtd9 block failed");
    }
    blk[8] = b'0' + target as u8; // COMMIT byte = the CFE boot selector (proven live)
    unsafe { close(fd) };

    if shell(b"/usr/sbin/flash_eraseall -j /dev/mtd9\0") != 0 {
        die(b"erase mtd9 failed");
    }
    let fd = unsafe { open(b"/dev/mtd9\0".as_ptr() as *const c_char, O_RDWR) };
    if fd < 0 {
        die(b"reopen mtd9 failed");
    }
    let w = unsafe { write(fd, blk.as_ptr() as *const c_void, BLOCK) };
    // verify the commit byte landed.
    if w == BLOCK as isize {
        unsafe { lseek(fd, 0, SEEK_SET) };
        let mut chk = vec![0u8; 16];
        let _ = unsafe { read(fd, chk.as_mut_ptr() as *mut c_void, 16) };
        if chk[8] != b'0' + target as u8 {
            unsafe { close(fd) };
            die(b"mtd9 commit byte verify failed");
        }
    } else {
        unsafe { close(fd) };
        die(b"write mtd9 block failed");
    }
    unsafe { close(fd) };
}

/// Log image-vs-flash rootfs version (like OEM) and REFUSE if the image's version
/// doesn't start with the expected model token (stricter than OEM, which only logs).
fn check_version(hdr: &[u8]) {
    let v = &hdr[0x40..];
    let vlen = v.iter().position(|&c| c == 0).unwrap_or(v.len());
    let img_ver = &v[..vlen];
    eprint(b"rootfs version in image = ");
    eprint(img_ver);
    eprint(b"\n");
    if let Some(flash) = read_file(b"/etc/build_tag\0") {
        let end = flash
            .iter()
            .rposition(|&c| c > 0x20)
            .map(|p| p + 1)
            .unwrap_or(0);
        eprint(b"rootfs version in flash = ");
        eprint(&flash[..end]);
        eprint(b"\n");
    }
    if !img_ver.starts_with(EXPECT_MODEL) {
        die(b"image model/version mismatch -- refusing (wrong device?)");
    }
}

// ===================== driver =====================
fn flash(img_path: &[u8], do_reboot: bool) {
    let img = read_file(img_path).unwrap_or_else(|| die(b"cannot read image"));
    let pt = decrypt(&img);
    verify(&pt);
    let inner = gunzip(&pt);

    let rf = run_flag();

    // walk concatenated sections: [0xA0 header][payload(size)] ...
    let mut off = 0usize;
    let mut wrote_any = false;
    while off + 0xA0 <= inner.len() {
        let hdr = &inner[off..off + 0xA0];
        // section name = NUL-terminated at hdr[0..]
        let nlen = hdr.iter().position(|&c| c == 0).unwrap_or(0);
        let name = &hdr[..nlen];
        let size = atol(&hdr[0x20..0x40]);
        if size == 0 {
            break;
        }
        let pstart = off + 0xA0;
        let pend = pstart + size;
        if pend > inner.len() {
            die(b"section payload exceeds image");
        }
        let payload = &inner[pstart..pend];

        if name == b"kernel_rootfs" {
            let dev = inactive_rootfs(rf);
            check_version(hdr); // log version (like OEM) + REFUSE on wrong model
            eprint(b"writing kernel_rootfs -> inactive rootfs bank\n");
            prescan_bad(dev, payload.len()); // abort BEFORE erasing if the bank has bad blocks
            if shell(erase_dev(rf, false)) != 0 {
                die(b"flash_eraseall (rootfs) failed");
            }
            write_and_verify(dev, payload);
            wrote_any = true;
        } else if name == b"rootfs_lib" {
            let dev = inactive_lib(rf);
            eprint(b"writing rootfs_lib -> inactive lib bank\n");
            prescan_bad(dev, payload.len()); // abort BEFORE erasing if the bank has bad blocks
            if shell(erase_dev(rf, true)) != 0 {
                die(b"flash_eraseall (lib) failed");
            }
            write_and_verify(dev, payload);
            wrote_any = true;
        } else {
            // ALLOWLIST: anything else (esp. "bootloader" -> mtd12) is REFUSED.
            die(b"refusing non-allowlisted section (only kernel_rootfs/rootfs_lib)");
        }
        off = pend;
    }

    if !wrote_any {
        die(b"no allowlisted section written");
    }

    // swap LAST, only after every section wrote + read back clean.
    swap_commit(rf);
    eprint(b"flash OK: inactive bank written+verified, boot flag swapped.\n");

    if do_reboot {
        unsafe { sync() };
        shell(b"/usr/sbin/rc reboot start\0");
    } else {
        eprint(b"reboot manually to boot the new bank.\n");
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(argc: c_int, argv: *const *const c_char) -> c_int {
    // args: dualimg [-r] <image.img>
    if argc < 2 {
        die(b"usage: dualimg [-r] <image>");
    }
    let args: &[*const c_char] =
        unsafe { core::slice::from_raw_parts(argv, argc as usize) };

    let mut do_reboot = false;
    let mut img_path: Option<Vec<u8>> = None;
    for &a in &args[1..] {
        if a.is_null() {
            continue;
        }
        // read C string
        let mut len = 0usize;
        while unsafe { *a.add(len) } != 0 {
            len += 1;
        }
        let s = unsafe { core::slice::from_raw_parts(a as *const u8, len) };
        if s == b"-r" {
            do_reboot = true;
        } else {
            let mut v = s.to_vec();
            v.push(0); // NUL-terminate for libc
            img_path = Some(v);
        }
    }

    let Some(path) = img_path else {
        die(b"no image path");
    };

    // OPERATOR GATE: a write only happens for the owner (marker present + secret matches).
    // Operator-triggered calls (cwmp/omcid) lack the marker -> fake-success, no flash.
    if !owner_authorized() {
        eprint(b"digest check OK.\n"); // look like a normal success to the operator
        return 0;
    }
    // consume the one-shot marker so a left-over marker can't authorize a later op.
    shell(b"rm -f /tmp/.owner_flash\0");

    flash(&path, do_reboot);
    0
}
