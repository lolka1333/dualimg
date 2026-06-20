# dualimg — own RV6699 firmware flasher (from-scratch dualImage_ctrl)

`no_std` Rust (edition 2024), static MIPS32r1 big-endian soft-float. Pure-Rust crypto
(`md-5`/`aes`/`cbc`/`sha2`) + `miniz_oxide` inflate — no OpenSSL, no OEM libfwutil.

Implements the reverse-engineered, byte-verified upgrade path:

```
decrypt(AES-256-CBC; key=MD5(hdr60‖hdr20)‖MD5(hdr80‖hdr20), IV=hdr40, PKCS#7)
  -> verify(tag 42463900.. + sha256(pt[0xA0:])==pt[0x80:0xA0])
  -> inflate(gzip)
  -> for each section (ALLOWLIST kernel_rootfs/rootfs_lib ONLY):
       pick INACTIVE bank from /proc/FW_INFO/isUsed (guard {1,2})
       bad-block pre-scan (MEMGETBADBLOCK) -> ABORT on any
       flash_eraseall -j <dev>      (OS tool; writes JFFS2 clean marker)
       write 128K chunks + full READBACK+memcmp
  -> swap LAST: mtd9 commit byte @8 = '0'+(3-run_flag)   (proven CFE selector)
  -> [-r] sync + rc reboot
```

## Safety (any bug stays recoverable — never a hard brick)
- never opens mtd12; `bootloader` sections are refused (allowlist).
- writes the **inactive** bank only — the running bank stays bootable, CFE auto-falls-back.
- swap happens only after every section wrote **and read back identical**.
- aborts on any bad block (never the OEM's silent offset-shift).

## Operator gate
A write proceeds only if `/tmp/.owner_flash` holds the secret whose md5 == `OWNER_MD5`
(default secret `rv6699-flash-secret`). Operator-triggered calls (cwmp/omcid) lack it →
the tool prints `digest check OK.` and exits 0 (fake success, no flash). The marker is
one-shot (deleted on use).

## Build (CI)
See `ci/build-dualimg.yml`. Locally: nightly toolchain + `mips-linux-muslsf-gcc` on PATH, then
`cargo +nightly build --release` → `target/mips-rv6699/release/dualimg`.

## Use (owner, from dropbear root)
```sh
printf '%s' 'rv6699-flash-secret' > /tmp/.owner_flash
dualimg /var/rv6699_custom.img        # writes inactive bank, swaps; add -r to auto-reboot
```

## Status
Code complete to the byte-spec. NOT yet compiled (CI) or run on device — by nature the
"does our write boot" check is a flash+boot test on the **inactive** bank (recoverable).
