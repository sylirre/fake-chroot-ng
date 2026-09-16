/* A guest whose text and data sit on adjacent 4 KiB pages, so that on a host
 * with a larger page size (16 KiB) the two PT_LOADs share one host page — the
 * shape of a 4 KiB-max-page-size object on an Android 16 KiB kernel. It runs
 * only if the page keeps BOTH execute (for _start) and write (for the store
 * into msg). Freestanding: no libc, linked with pageshare.ld. */
    .text
    .globl _start
_start:
    adrp x1, msg
    add  x1, x1, :lo12:msg
    mov  w2, #0x21              /* '!' */
    strb w2, [x1, #6]           /* .data must be writable */
    mov  x0, #1
    mov  x2, #8
    mov  x8, #64                /* write */
    svc  #0
    mov  x0, #0
    mov  x8, #94                /* exit_group */
    svc  #0
    .data
msg: .ascii "shared?\n"
