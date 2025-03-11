//
// Created by witch on 3/11/25.
//

#ifndef CBFS_LOAD_H
#define CBFS_LOAD_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "com.h"

#define TBOOT_LOAD_ADDR             0x1000000        //   adjust MLE base depending on spec if this doesn't work
#define CBFS_MASTER_HEAD_MAGIC     0x4F524243        //   orbc
#define CBFS_FILE_MAGIC            0x4C494E4B        //   link

extern void *CBFS_BASE_ADDR;

struct cbfs_master_header {
  uint32_t  magic;
  uint32_t  version;
  uint32_t  rom_size;
  uint32_t  boot_block_size;
  uint32_t  align;
  uint32_t  offset;
  uint32_t  architecture;
};

struct cbfs_file {
  uint32_t  magic;
  uint32_t  len;
  uint32_t  type;
  uint32_t  checksum;
  uint32_t  offset;
};

struct cbfs_file_attribute {
  uint32_t  tag;
  uint32_t  len;
  uint8_t   data[];
};

#define CBFS_ATTRIBUTE_TAG_NAME 0x4E414D45        // name

static inline uintptr_t align_up(uintptr_t addr, uint32_t align) {
  return ( addr + align - 1 ) & ~( align - 1 );
}

static int _strcmp(const char *s1, const char *s2) {
  while ( *s1 && *s1 == *s2 ) {
    s1++;
    s2++;
  }

  return *( unsigned char *)s1 - *( unsigned char *)s2;
}

struct cbfs_file *cbfs_find_file(const char *name) {
  struct cbfs_master_header *master_hdr = (struct cbfs_master_header *)CBFS_BASE_ADDR;
  master_hdr = (struct cbfs_master_header *)align_up((uintptr_t)CBFS_BASE_ADDR, 8);

  if (master_hdr->magic != CBFS_MASTER_HEAD_MAGIC) {
    serial_print("cbfs_find_file:  bad magic number\n");
    return NULL;
  }

  void *current = (void *)( (uintptr_t)CBFS_BASE_ADDR +   master_hdr->offset );
  void *end     = (void *)( (uintptr_t)CBFS_BASE_ADDR + master_hdr->rom_size );

  while ( current < end ) {
    struct cbfs_file *file = ( struct cbfs_file * )current;

    if ( file->magic == CBFS_FILE_MAGIC ) {
      void *attr_start = (void *)((uintptr_t)file + sizeof(struct cbfs_file));
      void *attr_end   = (void *)((uintptr_t)file + file->offset);
      const char *fname = NULL;

      while ( attr_start < attr_end ) {
        struct cbfs_file_attribute *attr = (struct cbfs_file_attribute *)attr_start;
        if ( attr->tag == CBFS_ATTRIBUTE_TAG_NAME ) {
          fname = ( const char * ) attr->data;
          break;
        }
        attr_start = (void *)((uintptr_t)attr_start + align_up(attr->len, 8));
      }

      if ( fname && _strcmp(fname, name) == 0 ) {
        serial_print("cbfs_find_file:  found file ");
        serial_print(name);
        serial_print(" @ ");
        serial_print_hex((uint32_t)file);
        serial_print("\n");
        return file;
      }
    }

    current = (void *)( (uintptr_t)file + align_up( file->offset + file->len, master_hdr->align ) );
  }

  serial_print("checkmate:  file ");
  serial_print(name);
  serial_print(" not found in CBFS\n");
  return NULL;
}

void *cbfs_load(const char *name, size_t *size) {
  struct cbfs_file *file = cbfs_find_file(name);
  if (!file) {
    return NULL;
  }

  void *file_data = (void *)((uintptr_t)file + file->offset);

  void *load_addr = (void *)TBOOT_LOAD_ADDR;
  memcpy(load_addr, file_data, file->len);

  if ( size ) {
    *size = file->len;
  }

  serial_print("cbfs_load:  loaded ");
  serial_print(name);
  serial_print(" to ");
  serial_print_hex((uint32_t)load_addr);
  serial_print(", size=");
  serial_print_hex(file->len);
  serial_print("\n");

  return load_addr;
}

#endif //CBFS_LOAD_H