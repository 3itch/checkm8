
/****************************************************************
 * Memory map
 ****************************************************************/

struct cb_header {
    UINT32 signature;
    UINT32 header_bytes;
    UINT32 header_checksum;
    UINT32 table_bytes;
    UINT32 table_checksum;
    UINT32 table_entries;
};

#define CB_SIGNATURE 0x4f49424C // "LBIO"

struct cb_memory_range {
    UINT64 start;
    UINT64 size;
    UINT32 type;
};

struct cb_memory {
    UINT32 tag;
    UINT32 size;
    struct cb_memory_range map[0];
};

struct cb_forward {
    UINT32 tag;
    UINT32 size;
    UINT64 forward;
};

#define CB_TAG_FORWARD 0x11

struct cb_cbmem_ref {
    UINT32 tag;
    UINT32 size;
    UINT64 cbmem_addr;
};

#define CB_TAG_CBMEM_CONSOLE 0x17

struct cbmem_console {
    UINT32 size;
    UINT32 cursor;
    UINT8  body[0];
} PACKED;

#define CBMC_CURSOR_MASK ((1 << 28) - 1)
#define CBMC_OVERFLOW (1 << 31)

static struct cbmem_console *cbcon = NULL;

static UINT16
ipchksum(char *buf, int count)
{
    UINT16 *p = (UINT16*)buf;
    UINT32 sum = 0;
    while (count > 1) {
        sum += *p;
        p++;
        count -= 2;
    }
    if (count)
        sum +=  *(UINT8*)p;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

// Try to locate the coreboot header in a given address range.
static struct cb_header *
find_cb_header(UINT64 addr, int len)
{
    UINT64 end = addr + len;
    for (; addr < end; addr += 16) {
        struct cb_header *cbh = (void*)addr;
        if (cbh->signature != CB_SIGNATURE)
            continue;
        UINT32 tsize = cbh->table_bytes;
        if (! tsize)
            continue;
        if (ipchksum((void*)addr, sizeof(*cbh)) != 0)
            continue;
        if (ipchksum((void*)addr + sizeof(*cbh), tsize)
            != cbh->table_checksum)
            continue;
        return cbh;
    }
    return NULL;
}

// Try to find the coreboot memory table in the given coreboot table.
void *
find_cb_subtable(struct cb_header *cbh, UINT32 tag)
{
    char *tbl = (char *)cbh + sizeof(*cbh);
    UINT32 count = cbh->table_entries;
    int i;
    for (i=0; i<count; i++) {
        struct cb_memory *cbm = (void*)tbl;
        tbl += cbm->size;
        if (cbm->tag == tag)
            return cbm;
    }
    return NULL;
}

struct cb_header *
find_cb_table(void)
{
    struct cb_header *cbh = find_cb_header(0, 0x1000);
    if (!cbh)
        return NULL;
    struct cb_forward *cbf = find_cb_subtable(cbh, CB_TAG_FORWARD);
    if (cbf) {
        //dprintf(3, "Found coreboot table forwarder.\n");
        cbh = find_cb_header(cbf->forward, 0x100);
        if (!cbh)
            return NULL;
    }
    return cbh;
}

static UINT32 STM_cursor = 0;

int init_cbcons(void)
{
    struct cb_header *cbh = find_cb_table();

    if (!cbh)
        goto fail;

    struct cb_cbmem_ref *cbref = find_cb_subtable(cbh, CB_TAG_CBMEM_CONSOLE);

    if (cbref) {
        cbcon = (void*)(UINT64)cbref->cbmem_addr;

	// set the cursor such that the STM console will not overwrite the
	// coreboot console output
	STM_cursor = cbcon->cursor & CBMC_CURSOR_MASK;
    }

    return 0;
fail:
    return -1;
}

void coreboot_debug_putc(char c)
{
#ifdef CONFIG_STM_CBMEM_CONSOLE
    if (!cbcon)
        return;

    UINT32 cursor = cbcon->cursor & CBMC_CURSOR_MASK;
    UINT32 flags = cbcon->cursor & ~CBMC_CURSOR_MASK;

    if (cursor >= cbcon->size)
        return; // Old coreboot version with legacy overflow mechanism.

    cbcon->body[cursor++] = c;
    if (cursor >= cbcon->size) {
        cursor = STM_cursor;
        flags |= CBMC_OVERFLOW;
    }
    cbcon->cursor = flags | cursor;
#endif
}

