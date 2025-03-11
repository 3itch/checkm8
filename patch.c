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
//#include <libpayload.h>
//#include <cbfs.h>
#include "com.h"
#include "cbfs_load.h"

#define TBOOT_LOAD_ADDR         0x1000000     //    adjust MLE base depending on spec if this doesn't work
#define VERIFY_INTEGRITY_OFFSET 0x80af10

void patch(const void* tboot_base) {
  void* verify_integrity_addr = (void*)((uint32_t)tboot_base + VERIFY_INTEGRITY_OFFSET);
  serial_print("checkmate:  patching verify_integrity @ ");
  serial_print_hex((uint32_t)verify_integrity_addr);
  serial_print("\n");

  /**************
  mov eax, 1; ret
  **************/
  uint8_t patch[] = {0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3};
  for (size_t i = 0; i < sizeof(patch); i++) {
    ((uint8_t*)verify_integrity_addr)[i] = patch[i];
  }

  serial_print("checkmate:    patched!\n");
}

void *memcpy(void *dest, const void *src, size_t n) {
  uint8_t *d = (uint8_t*)dest;
  const uint8_t *s = (const uint8_t*)src;

  size_t i;
  for ( i = 0; i < n; i++ ) {
    d[i] = s[i];
  }

  return dest;
}

//extern void* __cbfs_load(const char* name, size_t* size);
void* tboot_load() {
  size_t tboot_size;
  void* tboot_base = cbfs_load("tboot.gz", &size);
  if ( !tboot_addr ) {
    serial_print("checkmate:  failed to load tboot.gz\n");
    return NULL;
  }
  return tboot_base;

  size_t i;
  uint8_t* dest = (uint8_t*)TBOOT_LOAD_ADDR;
  for (i = 0; i < tboot_size; i++) {
    dest[i] = ((uint8_t*)tboot_addr)[i];
  }
  return (void*)TBOOT_LOAD_ADDR;
}

void shim_main() {
  serial_print("checkmate:  shim running post-SINIT\n");
  void* tboot_base = tboot_load();
  serial_print("checkmate:    tboot loaded @ ");
  serial_print_hex((uint32_t)tboot_base);
  serial_print("\n");

  patch(tboot_base);

  serial_print("checkmate: jumping to tboot entry\n");
  void (*tboot_entry)(void) = (void (*)(void))tboot_base;
  tboot_entry();
}