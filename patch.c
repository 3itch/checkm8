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
#include <elf.h>
#include "com.h"
#include "cbfs_load.h"
#include "coreboot_table.h"

#define VERIFY_INTEGRITY_OFFSET     0x80af10
#define CBFS_MASTER_HEADER_MAGIC  0x4F524243     //    orbc

struct mle_param_block {
  uint32_t  version;
  uint32_t  mle_entry;
  uint32_t  mle_start;
  uint32_t  mle_end;
  uint8_t   reserved[4];
}

void *CBFS_BASE_ADDR = NULL;

void *sinit_load() {
  size_t sinit_size;
  void *sinit_data = cbfs_load("sinit.bin", &sinit_size);

  if ( !sinit_data ) {
    serial_print("checkmate:  couldn't load sinit.bin\n");
    return NULL;
  }

  void *sinit_base = (void *)0x00000000;
  memcpy(sinit_base, sinit_data, sinit_size);

  return sinit_base;
}

void patch(const void* tboot_base) {
  void* verify_integrity_addr = (void*)( (uint32_t)tboot_base + VERIFY_INTEGRITY_OFFSET );
  serial_print("checkmate:  patching verify_integrity @ ");
  serial_print_hex( (uint32_t)verify_integrity_addr );
  serial_print("\n");

  size_t i;
  uint8_t patch[] = {0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3};     //    mov eax, 1;  ret
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
  serial_print(" to ");
  serial_print_hex((uint32_t)end);
  serial_print("\n");

  for ( uintptr_t addr = start; addr < end; addr += step ) {
    volatile uint32_t *ptr = ( volatile uint32_t * )addr;

    if ( *ptr == CBFS_MASTER_HEADER_MAGIC ) {
      serial_print("checkmate:  found CBFS @ ");
      serial_print_hex((uint32_t)addr);
      serial_print("\n");

      return (void *)addr;
    }
  }

  serial_print("checkmate:  CBFS base wasn't found in range\n");
  return NULL;
}

extern void call_sinit(void);
void mpb_setup(void *tboot_entry, size_t tboot_size) {
  struct mle_param_block mpb = {
    .version = 6,
    .mle_entry = (uint32_t)tboot_entry,
    .mle_start = TBOOT_LOAD_ADDR,
    .mle_end = TBOOT_LOAD_ADDR + tboot_size,
    .reserved = {0},
  };

  void *mpb_base = (void *)0x1000;      // estimate,  adjust based on config or spec
  memcpy(mpb_base, &mpb, sizeof(mpb));
}

//extern void* __cbfs_load(const char* name, size_t* size);
void *load_elf(void *data, size_t size) {
  Elf32_Ehdr *ehdr = (Elf32_Ehdr *)data;
  Elf32_Phdr *phdr = (Elf32_Phdr *)( data + ehdr->e_phoff );

  int i;
  for ( i = 0; i < ehdr->e_phnum; i++ ) {
    if ( phdr[i].p_type == PT_LOAD ) {
      if ( !*base_addr ) *base_addr = (void *)phdr[i].p_vaddr;
      memcpy((void *)phdr[i].p_vaddr, data + phdr[i].p_offset, phdr[i].p_filesz);
    }
  }

  return (void *)ehdr->e_entry;
}

void shim_main() {
  serial_print("checkmate:  preparing MLE -SINIT\n");

//  uintptr_t search_start = 0xFF000000;     //  -16MB
//  uintptr_t search_end   = 0xFFFFFFFF;     //    4GB
//  uintptr_t search_step  =       4096;     //    page size ( 4KB ) increments
//                                           //        see spec for page size..
//

//  CBFS_BASE_ADDR = bruteforce_cbfs_base_addr(search_start, search_end, search_step);
  CBFS_BASE_ADDR = find_cbfs_base_addr();
  if ( !CBFS_BASE_ADDR ) {
    serial_print("checkmate:      failed to find CBFS base addr\n");
    return;
  }

  size_t tboot_size;
  void *tboot_data = cbfs_load("tboot-bin", &tboot_size);
  if ( !tboot_data ) {
    serial_print("checkmate:      failed to load tboot-bin\n");
    return;
  }

  void *tboot_base;
  void *tboot_entry = load_elf(tboot_data, tboot_size, &tboot_base);
  if ( !tboot_entry ) {
    serial_print("checkmate:      failed to parse tboot ELF\n");
    return;
  }
  
  serial_print("checkmate:  tboot loaded @ ");
  serial_print_hex((uint32_t)tboot_entry);
  serial_print("\n");

  patch(tboot_base);

  void *sinit_base = sinit_load();
  if ( !sinit_base ) {
    serial_print("checkmate:      failed to load sinit\n");
    return;
  }

  mpb_setup(tboot_entry, tboot_size);

  serial_print("checkmate:  invoking sinit\n");
  call_sinit();
}