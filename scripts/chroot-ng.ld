/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Sylirre */
/* Link chroot-ng at a high fixed base (64 GiB), clear of the 0x400000 region
 * where non-PIE ET_EXEC guests (e.g. gcc's cc1) load. Setting the location
 * counter explicitly makes the first PT_LOAD *start* at the base — unlike
 * -Ttext/-Ttext-segment/--image-base, which on lld pad a segment from the
 * default 0x200000 up to the base (a ~64 GiB segment that still covers, and
 * clobbers, 0x400000). Works with both GNU ld and lld.
 *
 * FILEHDR/PHDRS place the ELF header + program headers in the text segment;
 * SIZEOF_HEADERS reserves room for them so .text is correctly file/vaddr
 * aligned. Only the allocatable sections chroot-ng actually emits are listed
 * (.text incl. the svc gate, .rodata, .eh_frame, .data, .bss). */
ENTRY(_start)

PHDRS
{
    text PT_LOAD FILEHDR PHDRS FLAGS(5); /* R E */
    data PT_LOAD FLAGS(6);               /* R W */
}

SECTIONS
{
    . = 0x1000000000 + SIZEOF_HEADERS;

    .text : {
        KEEP(*(.text.gate))
        *(.text .text.*)
    } :text
    .rodata : { *(.rodata .rodata.*) } :text
    .eh_frame : { *(.eh_frame) } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .data : { *(.data .data.*) } :data
    .bss : { *(.bss .bss.* COMMON) } :data

    /DISCARD/ : { *(.note .note.* .comment .gnu.hash .hash .dynsym .dynstr) }
}
