OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
OUTPUT_ARCH(i386)
ENTRY(start)
PHDRS
{
  text PT_LOAD ;
}
SECTIONS
{
  . = 0x0800000;
  .text : {
 *(.tboot_multiboot_header)
  . = ALIGN(4096);
 *(.mlept)
  _mle_start = .;
 *(.text)
 *(.fixup)
 *(.gnu.warning)
 *(.comment)
 } :text = 0x9090
  .rodata : { *(.rodata) *(.rodata.*) }
  . = ALIGN(4096);
  _mle_end = .;
  .data : {
 *(.data)
 *(.tboot_shared)
 CONSTRUCTORS
 }
  . = ALIGN(4096);
  __bss_start = .;
  .bss : {
 *(.bss.stack_aligned)
 *(.bss.page_aligned)
 *(.bss)
 }
  _end = . ;
}
