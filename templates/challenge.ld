/*
 * Linker script for Reverse Tutor challenges: 32-bit i386, non-PIE.
 *
 * Why a custom script rather than the defaults: the student analyses this in
 * IDA's 32-bit build (`ida.exe`), and a predictable layout is worth more there
 * than any linker convenience. This script produces the classic i386 teaching
 * image:
 *
 * - the load address is 0x08048000, where 32-bit Linux puts a non-PIE executable,
 *   so IDA's default base matches and every address the tutor quotes is the
 *   address the student sees on screen;
 * - `.text` starts at 0x08049000, a round address they can name from memory;
 * - `.rodata` gets its own page right after the code, so the constant they have
 *   to find is visibly separate from the code that reads it.
 *
 * The single `AT` load address below is what fixes the base; the two output
 * sections are then placed at fixed virtual addresses.
 */
ENTRY(_start)

SECTIONS
{
    . = 0x08048000;
    __rt_image_start = .;

    .text 0x08049000 : AT(0x1000)
    {
        *(.text .text.*)
    }

    .rodata ALIGN(0x1000) : AT(ALIGN(LOADADDR(.text) + SIZEOF(.text), 0x1000))
    {
        *(.rodata .rodata.*)
        *(.data .data.*)
    }

    /DISCARD/ :
    {
        *(.comment)
        *(.note .note.*)
        *(.eh_frame .eh_frame_hdr)
    }
}
