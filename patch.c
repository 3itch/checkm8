//
// Created by witch on 3/10/25.
//
/*
         __               __             _______
   .----|  |--.-----.----|  |--.--------|   _   |
   |  __|     |  -__|  __|    <|        |.  |   |
   |____|__|__|_____|____|__|__|__|__|__|.  _   |
                                        |:  1   |
                                        |::.. . |
                                        `-------'
    TBoot patching, because Intel TXT
                  is horrendously bad...

    file:         patch.c
    description:  custom patching coreboot shim
*/

#include <stdint.h>
#include <stddef.h>

#define TBOOT_BASE_ADDR 0x100000

#define VERIFY_INTEGRITY_OFFSET 0x80af10

void serial_putc(char c) {
  volatile uint8_t* serial_port = (volatile uint8_t*)0x3f8;
  while ( ! (*serial_port & 0x20) );
  *serial_port = c;
}

void serial_print(const char* str) {
  while (*str) {
    serial_putc(*str++);
  }
}

void serial_print_hex(uint32_t val) {
  const char hex[] = "0123456789ABCDEF";
  serial_print("0x");

  int i;
  for (i = 28; i >= 0; i -= 4) {
    serial_putc(hex[(val >> i) & 0xf]);
  }
}

void patch(void) {
  void* verify_integrity_addr = (void*)(TBOOT_BASE_ADDR + VERIFY_INTEGRITY_OFFSET);

  serial_print("checkmate:  patching verify_integrity @ ");
  serial_print_hex((uint32_t)verify_integrity_addr);
  serial_print("\n");

  /**************
  mov eax, 1; ret
  **************/
  uint8_t patch[] = {0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3};

  size_t i;
  for (i = 0; i < sizeof(patch); i++) {
    ((uint8_t*)verify_integrity_addr)[i] = patch[i];
  }

  serial_print("checkmate:      patched!");
}

void shim_main() {
  serial_print("checkmate:  tboot base address @ ");
  serial_print_hex(TBOOT_BASE_ADDR);
  serial_print("\n");

  patch();

  serial_print("checkmate:      jumping to tboot entry");
  void (*tboot_entry)(void) = (void (*)(void))TBOOT_BASE_ADDR;
  tboot_entry();
}