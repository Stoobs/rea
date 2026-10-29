# Retro 68000 targets: Amiga, Atari ST family, classic Mac

Use this guide when the target is 68000-family code from an Amiga, an Atari
ST/STE/TT/Falcon, or a pre-PowerPC Macintosh, or a ROM from one of them. REA has
no container lane for these platforms yet. The only 68k route is the headerless
raw-binary lane, so most of the work is choosing the right bytes and the right
base address before opening, and recording those choices as analysis decisions.

Omitting `format` does not detect these containers. Do not open a hunk file,
`.PRG` or resource fork directly and treat a refusal as a property of the target.

## Identify the container from bytes

Classify with the bytes, not the suffix. Keep the original file digest next to
every derived file in the finding ledger.

| Leading bytes or layout                           | Container                                                   |
| ------------------------------------------------- | ----------------------------------------------------------- |
| `00 00 03 F3`                                     | Amiga hunk load file (`HUNK_HEADER`)                        |
| `00 00 03 E7`                                     | Amiga hunk object (`HUNK_UNIT`); not loadable               |
| `60 1A`                                           | Atari GEMDOS program (`.PRG` `.TOS` `.TTP` `.APP` `.ACC`)   |
| `00 05 16 00` / `00 05 16 07`                     | AppleSingle / AppleDouble (Mac forks)                       |
| 128-byte MacBinary header, then forks             | MacBinary (Mac forks)                                       |
| Resource map listing `CODE` resources             | Classic Mac 68k application                                 |
| `11 11 4E F9` / `11 14 4E F9`                     | Amiga Kickstart ROM, 256 KiB / 512 KiB                      |
| OSHEADER; long at offset 8 is `os_beg`            | Atari TOS ROM; `os_beg` is the mapped base                  |
| 901,120 or 1,802,240 bytes; DOS disks start `DOS` | Amiga ADF disk image (DD / HD); non-DOS disks have no magic |
| `0E 0F` / 512-byte-sector FAT12 image             | Atari `.MSA` / `.ST` disk image                             |
| `42 44` (`BD`) at offset 1024                     | HFS volume (raw, or after the DiskCopy 4.2 header)          |

A Mac application's code lives in its resource fork. A data fork alone is not
the program.

## Unpack before analysis

- Disk images: extract members with format tools outside REA, for example
  amitools `xdftool` for ADF, mtools for `.ST`, `machfs` or hfsutils for HFS.
- Non-DOS Amiga disks: the 1024-byte boot block holds code from byte 12, which
  Kickstart calls with `A6` = ExecBase. Many games load the rest with their own
  track loader. Slice the boot block from byte 12 into its own file and open
  that; the base is an analysis choice because the code is loaded wherever exec
  allocates it.
- Crunched executables (PowerPacker, Imploder, Pack-Ice and similar): decompress
  with an ordinary decompressor for that cruncher into a new file, then analyse
  the new file. Record the decompressor and version.
- Copy protection (encrypted loaders, Copylock-style checks, encrypted `CODE`
  resources, disk-key checks): REA's contribution scope excludes dedicated
  protection-defeat workflows. Report the protection as an observation and do
  not automate its removal.

## Flatten, relocate and open

Until container lanes exist, build a flat image, then open it as raw m68k.

1. Choose a base. It is an analysis decision, not an observation; say so.
   - Amiga hunk: lay hunks out in order at an even base, each 8-byte aligned,
     and keep the start of each hunk. Each size longword carries memory flags
     in its top two bits (bit 30 chip, bit 31 fast; both set means a flags
     longword follows). Chip placement matters to hardware access, not decode.
   - Atari PRG: TEXT, DATA and BSS follow a 256-byte basepage. Pick TEXT's base
     and remember that the basepage sits 256 bytes below it.
   - Mac: each `CODE` segment loads into the heap separately. Pick a base per
     segment and one `A5` value; `CODE 0` gives the sizes above and below `A5`.
2. Apply relocations to the flat copy, never to the original file.
   - Amiga: `HUNK_RELOC32` (`0x3EC`) lists, per target hunk, offsets of
     longwords that receive that hunk's base. `HUNK_RELOC32SHORT` (`0x3FC`)
     uses 16-bit offsets; some linkers emit `0x3F7` for it in load files. The
     amitools hunk library can relocate segments to chosen addresses.
   - Atari: the fixup table follows the symbol table. Its first longword is the
     offset of the first fixup from TEXT (zero means none); then bytes follow:
     `0` ends, `1` advances 254 bytes, an even `n` advances `n` and fixes. Each
     fixed longword receives TEXT's base. A nonzero `ph_absflag` means no fixups.
   - Mac near-model `CODE` segments are PC-relative or `A5`-relative and need no
     relocation. A far-model segment (first word `0xFFFF`) carries its own
     relocation data; treat it as unsupported by this recipe and say so.
3. Open with `open_binary`: `format: "raw-binary"`, `architecture: "m68k"`,
   `entry_point` = the base (file offset 0 maps there). Run
   `inspect_native_load_image` and check the mapped bytes before trusting
   function analysis.
4. Seed what auto-analysis cannot reach with `REA_GHIDRA_SEED_FILE`
   (`address<TAB>kind[<TAB>name]`): `function` seeds for hunk and segment starts,
   jump-table targets and `HUNK_SYMBOL` / DRI symbol names; `label` seeds for
   mapped data. The seed file is read where REA starts. Prefer a CLI command
   with the variable set for that run; do not restart the user's MCP client
   without asking. Label seeds cannot name unmapped hardware registers; keep
   those names in the finding ledger or in `annotate_native_function` comments.

## Name OS calls

Each platform calls its OS in a recognizable shape. The call site is observed;
the name attached to it is often an inference. Label it as such.

| Platform           | Call shape                                                               | What establishes the name                                                                                                                                                                                                                         |
| ------------------ | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Amiga              | `jsr -n(a6)`; 6-byte vectors, first public function at `-30`             | Library base in `A6`: ExecBase is read from address 4; other bases come from `OpenLibrary` results. Offsets map to names through the library's `.fd` file (bring your own NDK). The library is inferred unless value flow ties `A6` to that base. |
| Amiga (SAS/C, GCC) | small-data access through `A4`                                           | `A4` set from the linker's data base in startup code.                                                                                                                                                                                             |
| Atari              | `trap #1` GEMDOS, `trap #13` BIOS, `trap #14` XBIOS                      | Function number = the last word pushed before the trap. Observed only when that push is a constant in the same block.                                                                                                                             |
| Atari              | `trap #2` with `D0` = `$C8` (AES) or `$73` (VDI); Line-A `$A000`–`$A00F` | `D0` value and the parameter block it points to.                                                                                                                                                                                                  |
| Mac                | A-line word `$Axxx`; bit 11 set = Toolbox, clear = OS trap               | Trap word is observed; its name comes from a trap list (bring your own).                                                                                                                                                                          |
| Mac                | `jsr n(a5)` with `n` ≥ 32                                                | Jump-table entry. `CODE 0` maps it to a segment and offset; unloaded entries hold `move.w #seg,-(sp)` and `_LoadSeg`.                                                                                                                             |
| Mac                | name string after `rts`, `rtd` or `jmp (a0)`                             | MacsBug procedure names emitted by many compilers; observed names, not debug info.                                                                                                                                                                |

Use `trace_native_values` on the register or stack slot before naming a call.
Do not name every `jsr -n(a6)` from offset alone: the same offset means
different functions in different libraries.

## CPU variant and addressing

- The raw lane binds Ghidra `68000:BE:32:default`, which decodes the 68040
  superset. 32-bit multiply or divide, bitfield ops, `extb.l` or scaled index
  modes in a title meant for a 68000 mean either a later-CPU code path or data
  decoded as code. Check before reporting either.
- 68000 machines and Macs in 24-bit mode ignore the top address byte. Mac
  Memory Manager master pointers keep flags there. REA does not mask addresses;
  treat a high-byte variant of a mapped address as an alias, not a new region.
- Exception vectors (`$008`–`$3FF`) and system variables are outside a program
  image. Writes to them are observations of intent, not of installed handlers.

## Hardware access

Hardware windows are unmapped in a flat program image, so accesses appear as
absolute constants. Name the window in findings; static access alone does not
show device behaviour.

| Machine      | Window                                                                                                                                     |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Amiga        | custom chips `$DFF000`–`$DFF1FF`; CIA-A `$BFE001` (odd bytes); CIA-B `$BFD000` (even bytes); chip RAM from `$000000`                       |
| Atari ST/STE | video `$FF8200`; DMA/FDC `$FF8600`; YM2149 `$FF8800`; STE DMA sound `$FF8900`; STE blitter `$FF8A00`; MFP 68901 `$FFFA00`; ACIAs `$FFFC00` |
| Mac          | low-memory globals `$0000`–`$0AFF` (for example `Ticks` at `$16A`, `CurrentA5` at `$904`); VIA, SCC and IWM addresses depend on the model  |

ROM bases: Kickstart 1.x at `$FC0000`, 2.0 and later at `$F80000`; TOS 1.00–1.04
at `$FC0000`, 1.06 and later at `$E00000`; compact Mac ROMs at `$400000`. Open a
ROM as raw m68k at that base and confirm with the ROM's own header.

## Runtime observation through an emulator

REA's GDB session is Linux-only and its console is unrestricted. When the
user's emulator exposes a GDB remote stub, start a GDB session with a GDB build
that supports m68k and use `target remote host:port` from `gdb_console`. The
observations then come from the emulated machine.

Record the emulator and version, CPU and chipset model, ROM or OS version, disk
image digest and configuration with every runtime finding; they are part of the
evidence. Emulator accuracy is a residual unknown when timing, DMA contention or
undocumented behaviour matters.

## Reconstruction and recompilation

Pick the strategy from the goal: understanding (pseudocode and annotations),
porting (static recompilation with a platform runtime), or preservation (keep
the binary and emulate). Then:

1. Inventory the OS and hardware surface first: every trap, library call and
   hardware window, with call-site counts. It scopes the runtime work.
2. Treat Ghidra pseudocode as a reading aid. Its types, flag handling and stack
   layout are inferences. A recompiler should lift instructions mechanically
   (explicit CPU state with `X N Z V C`, big-endian memory accessors) and
   replace functions with idiomatic C only after they are verified.
3. Record each unresolved indirect target as an unknown: `jmp (pc,dn)` tables,
   Mac jump-table calls, function pointers, self-modifying code and code copied
   to chip RAM are common. Resolve them with runtime traces, not guesses, and
   feed each resolved target back as a `function` seed.
4. Size the runtime to the title. OS-friendly applications can call host
   replacements for traps and library vectors. Programs that drive the hardware
   directly, including most Amiga and ST games, need lifted CPU code over
   emulated chips; a fully native runtime is rarely realistic for them.
5. Verify by differential execution. Run the original under an emulator core
   and the rebuilt program on the same inputs; compare registers and memory
   writes at function boundaries or frames. Express each function or OS call as
   a reviewed obligation in `build_reconstruction_obligation_ledger`. Emulator
   traces are not a supported original-process authority, so these obligations
   stay open; state that limitation instead of claiming closure.
6. Use `match_native_functions` and `compare_functions` across two releases of
   the same title (for example OCS and AGA builds, or two Mac versions) to carry
   names and spot changed routines.

Existing outside projects show the runtime side: amitools `vamos` implements
AmigaOS `exec` and `dos` at the API level, and macrecomp lifts Mac 68k code to C
over a Toolbox layer. They are not part of REA; check their licences and scope
before reusing code.
