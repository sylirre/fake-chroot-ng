/* Text at the first 4 KiB page, data at the next: one 16 KiB host page. */
ENTRY(_start)
SECTIONS {
  . = 0x400000;
  .text : { *(.text) }
  . = 0x401000;
  .data : { *(.data) }
}
