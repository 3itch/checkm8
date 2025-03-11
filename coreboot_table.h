//
// Created by witch on 11/03/25.
//

#include <stdint.h>
#include <stddef.h>
#include "com.h"

#ifndef COREBOOT_TABLE_H
#define COREBOOT_TABLE_H

#define COREBOOT_TB_MAGIC  0x43425254        //  cbrt
#define COREBOOT_TB_CBFS         0x14        //  cbfs entry tag

struct coreboot_tb_header {
  uint32_t magic;
  uint32_t header_bytes;
  uint32_t tb_bytes;
  uint32_t tb_checksum;
  uint32_t tb_entries;
};

struct coreboot_tb_entry {
  uint32_t tag;
  uint32_t size;
};

void *find_cbfs_base_addr() {
  for ( uintptr_t addr = 0x00000; addr < 0xFFFFF; addr += 16 ) {
    struct coreboot_tb_header *hdr = ( struct coreboot_tb_header * )addr;
    if ( hdr->magic == COREBOOT_TB_MAGIC ) {
      serial_print("coreboot_table:  found coreboot tables @ ");
      serial_print_hex((uint32_t)hdr);
      serial_print("\n");

      uint32_t i;
      void *entry_ptr = (void *)(hdr + 1);
      for ( i = 0; i < hdr->tb_entries; i++ ) {
        struct coreboot_tb_entry *entry = ( struct coreboot_tb_entry * )entry_ptr;
        if ( entry->tag == COREBOOT_TB_CBFS ) {
          void *cbfs_base = *(void **)(entry + 1);
          serial_print("coreboot_table:    found CBFS base @ ");
          serial_print_hex((uint32_t)cbfs_base);
          serial_print("\n");

          return cbfs_base;
        }
        entry_ptr = (void *)((uintptr_t)entry_ptr + entry->size);
      }
    }
  }

  serial_print("coreboot_table:  couldn't find coreboot table\n");
  return NULL;
}

#endif //COREBOOT_TABLE_H