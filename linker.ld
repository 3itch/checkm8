ENTRY(shim_main)
SECTIONS {
  . = 0x1000000;        /*  load at 1MB  */
  .text : {
    *(.text)
  }
  .data : {
    *(.data)
  }
  .bss : {
    *(.bss)
  }
}
