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
#include "com.h"
#include "cbfs_load.h"
//#include "coreboot_table.h"

#define TBOOT_LOAD_ADDR            0x1000000     //    adjust MLE base depending on spec if this doesn't work
#define VERIFY_INTEGRITY_OFFSET     0x80af10
#define CBFS_MASTER_HEADER_MAGIC  0x4F524243     //    orbc

void *CBFS_BASE_ADDR = NULL;

void patch(const void* tboot_base) {
  void* verify_integrity_addr = (void*)((uint32_t)tboot_base + VERIFY_INTEGRITY_OFFSET);
  serial_print("checkmate:  patching verify_integrity @ ");
  serial_print_hex((uint32_t)verify_integrity_addr);
  serial_print("\n");

                  /*******************/
                  // mov eax, 1; ret //             why the fuck am i doing this
  size_t i;       /*******************/
  uint8_t patch[] = {0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3};
  for (i = 0; i < sizeof(patch); i++) {
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


//            since i'm doing this blindly without access to the coreboot.rom
//                          i'm just going to brute-force it because it's way
//                                                       easier than guessing.
void *bruteforce_cbfs_base_addr(uintptr_t start, uintptr_t end, uint32_t step) {
  serial_print("checkmate:  brute-forcing CBFS base addr from @ ");
  serial_print_hex((uint32_t)start);
  serial_print("\n");
  serial_print(" to ");
  serial_print_hex((uint32_t)end);
  serial_print("\n");

  for ( uintptr_t addr = start; addr < end; addr += step ) {
    volatile uint32_t *ptr = ( volatile uint32_t * )addr;

    if ( *ptr == CBFS_MASTER_HEADER_MAGIC ) {
      serial_print("checkmate:  patching CBFS @ ");
      serial_print_hex((uint32_t)addr);
      serial_print("\n");

      return (void *)addr;
    }
  }

  serial_print("checkmate:  CBFS base wasn't found in range\n");
  return NULL;
}

//extern void* __cbfs_load(const char* name, size_t* size);
void* tboot_load() {
  size_t tboot_size;
  void* tboot_base = cbfs_load("tboot.gz", &tboot_size);
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


  uintptr_t search_start = 0xFF000000;     //  -16MB
  uintptr_t search_end   = 0xFFFFFFFF;     //    4GB
  uintptr_t search_step  =       4096;     //    page size ( 4KB ) increments
                                           //        see spec for page size..

  CBFS_BASE_ADDR = bruteforce_cbfs_base_addr(search_start, search_end, search_step);
  if ( !CBFS_BASE_ADDR ) {
    serial_print("checkmate:  failed to find CBFS base addr\n");
    return;
  }

  void* tboot_base = tboot_load();
  serial_print("checkmate:    tboot loaded @ ");
  serial_print_hex((uint32_t)tboot_base);
  serial_print("\n");

  patch(tboot_base);

  serial_print("checkmate: jumping to tboot entry\n");
  void (*tboot_entry)(void) = (void (*)(void))tboot_base;
  tboot_entry();
}