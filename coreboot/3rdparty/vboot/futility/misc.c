/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#if !defined(HAVE_MACOS) && !defined(__FreeBSD__) && !defined(__OpenBSD__)
#include <linux/fs.h>		/* For BLKGETSIZE64 */
#include <sys/sendfile.h>
#else
#include <copyfile.h>
#endif
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "2common.h"
#include "2sha.h"
#include "2sysincludes.h"
#include "cgptlib_internal.h"
#include "file_type.h"
#include "futility.h"
#include "futility_options.h"
#include "host_misc.h"

/* Default is to support everything we can */
enum vboot_version vboot_version = VBOOT_VERSION_ALL;

int debugging_enabled;
void vb2ex_printf(const char *func, const char *format, ...)
{
	if (!debugging_enabled)
		return;

	va_list ap;
	va_start(ap, format);
	if (func)
		fprintf(stderr, "DEBUG: %s: ", func);
	vfprintf(stderr, format, ap);
	va_end(ap);
}

static int is_null_terminated(const char *s, int len)
{
	len--;
	s += len;
	while (len-- >= 0)
		if (!*s--)
			return 1;
	return 0;
}

static inline uint32_t max(uint32_t a, uint32_t b)
{
	return a > b ? a : b;
}

enum futil_file_type ft_recognize_gbb(uint8_t *buf, uint32_t len)
{
	struct vb2_gbb_header *gbb = (struct vb2_gbb_header *)buf;

	if (memcmp(gbb->signature, VB2_GBB_SIGNATURE, VB2_GBB_SIGNATURE_SIZE))
		return FILE_TYPE_UNKNOWN;
	if (gbb->major_version > VB2_GBB_MAJOR_VER)
		return FILE_TYPE_UNKNOWN;
	if (sizeof(struct vb2_gbb_header) > len)
		return FILE_TYPE_UNKNOWN;

	/* close enough */
	return FILE_TYPE_GBB;
}

int futil_valid_gbb_header(struct vb2_gbb_header *gbb, uint32_t len,
			   uint32_t *maxlen_ptr)
{
	if (len < sizeof(struct vb2_gbb_header))
		return 0;

	if (memcmp(gbb->signature, VB2_GBB_SIGNATURE, VB2_GBB_SIGNATURE_SIZE))
		return 0;
	if (gbb->major_version != VB2_GBB_MAJOR_VER)
		return 0;

	/* Check limits first, to help identify problems */
	if (maxlen_ptr) {
		uint32_t maxlen = gbb->header_size;
		maxlen = max(maxlen,
			     gbb->hwid_offset + gbb->hwid_size);
		maxlen = max(maxlen,
			     gbb->rootkey_offset + gbb->rootkey_size);
		maxlen = max(maxlen,
			     gbb->bmpfv_offset + gbb->bmpfv_size);
		maxlen = max(maxlen,
			     gbb->recovery_key_offset + gbb->recovery_key_size);
		*maxlen_ptr = maxlen;
	}

	if (gbb->header_size != EXPECTED_VB2_GBB_HEADER_SIZE ||
	    gbb->header_size > len)
		return 0;
	if (gbb->hwid_offset < EXPECTED_VB2_GBB_HEADER_SIZE)
		return 0;
	if ((uint64_t)gbb->hwid_offset + gbb->hwid_size > len)
		return 0;
	if (gbb->hwid_size) {
		const char *s = (const char *)
			((uint8_t *)gbb + gbb->hwid_offset);
		if (!is_null_terminated(s, gbb->hwid_size))
			return 0;
	}
	if (gbb->rootkey_offset < EXPECTED_VB2_GBB_HEADER_SIZE)
		return 0;
	if ((uint64_t)gbb->rootkey_offset + gbb->rootkey_size > len)
		return 0;

	if (gbb->bmpfv_offset < EXPECTED_VB2_GBB_HEADER_SIZE)
		return 0;
	if ((uint64_t)gbb->bmpfv_offset + gbb->bmpfv_size > len)
		return 0;
	if (gbb->recovery_key_offset < EXPECTED_VB2_GBB_HEADER_SIZE)
		return 0;
	if ((uint64_t)gbb->recovery_key_offset + gbb->recovery_key_size > len)
		return 0;

	/* Seems legit... */
	return 1;
}

/* For GBB v1.2 and later, print the stored digest of the HWID (and whether
 * it's correct). Return true if it is correct. */
int print_hwid_digest(struct vb2_gbb_header *gbb, const char *banner)
{
	FT_READABLE_PRINT("%s", banner);
	FT_PARSEABLE_PRINT("hwid::digest::algorithm::2::SHA256\n");
	FT_PARSEABLE_PRINT("hwid::digest::hex::");

	/* There isn't one for v1.1 and earlier, so assume it's good. */
	if (gbb->minor_version < 2) {
		printf("<none>\n");
		FT_PARSEABLE_PRINT("hwid::digest::ignored\n");
		return 1;
	}

	uint8_t *buf = (uint8_t *)gbb;
	char *hwid_str = (char *)(buf + gbb->hwid_offset);
	int is_valid = 0;
	struct vb2_hash hash;

	if (VB2_SUCCESS == vb2_hash_calculate(false, buf + gbb->hwid_offset,
					      strlen(hwid_str), VB2_HASH_SHA256,
					      &hash)) {
		int i;
		is_valid = 1;
		/* print it, comparing as we go */
		for (i = 0; i < sizeof(hash.sha256); i++) {
			printf("%02x", gbb->hwid_digest[i]);
			if (gbb->hwid_digest[i] != hash.sha256[i])
				is_valid = 0;
		}
	}

	FT_PRINT_RAW("", "\n");
	FT_PRINT("   %s\n", "hwid::digest::%s\n", is_valid ? "valid" : "invalid");
	return is_valid;
}

/* Deprecated. Use futil_set_gbb_hwid in future. */
/* For GBB v1.2 and later, update the hwid_digest field. */
void update_hwid_digest(struct vb2_gbb_header *gbb)
{
	/* There isn't one for v1.1 and earlier */
	if (gbb->minor_version < 2)
		return;

	uint8_t *buf = (uint8_t *)gbb;
	char *hwid_str = (char *)(buf + gbb->hwid_offset);
	struct vb2_hash hash;

	vb2_hash_calculate(false, buf + gbb->hwid_offset, strlen(hwid_str),
			   VB2_HASH_SHA256, &hash);
	memcpy(gbb->hwid_digest, hash.raw, sizeof(gbb->hwid_digest));
}

/* Sets the HWID string field inside a GBB header. */
int futil_set_gbb_hwid(struct vb2_gbb_header *gbb, const char *hwid)
{
	uint8_t *to = (uint8_t *)gbb + gbb->hwid_offset;
	struct vb2_hash hash;
	size_t len;

	assert(hwid);
	len = strlen(hwid);
	if (len >= gbb->hwid_size)
		return -1;

	/* Zero whole area so we won't have garbage after NUL. */
	memset(to, 0, gbb->hwid_size);
	memcpy(to, hwid, len);

	/* major_version starts from 1 and digest must be updated since v1.2. */
	if (gbb->major_version == 1 && gbb->minor_version < 2)
		return 0;

	VB2_TRY(vb2_hash_calculate(false, to, len, VB2_HASH_SHA256, &hash));
	memcpy(gbb->hwid_digest, hash.raw, sizeof(gbb->hwid_digest));
	return VB2_SUCCESS;
}

int futil_copy_file(const char *infile, const char *outfile)
{
	VB2_DEBUG("%s -> %s\n", infile, outfile);

	int ifd, ofd;
	if ((ifd = open(infile, O_RDONLY)) == -1) {
		ERROR("Cannot open '%s', %s.\n", infile, strerror(errno));
		return -1;
	}
	if ((ofd = creat(outfile, 0660)) == -1) {
		ERROR("Cannot open '%s', %s.\n", outfile, strerror(errno));
		close(ifd);
		return -1;
	}
	struct stat finfo = {0};
	if (fstat(ifd, &finfo) < 0) {
		ERROR("Cannot fstat '%s' as %s.\n", infile, strerror(errno));
		close (ifd);
		close (ofd);
		return -1;
	}
#if !defined(HAVE_MACOS) && !defined(__FreeBSD__) && !defined(__OpenBSD__)
	ssize_t ret = sendfile(ofd, ifd, NULL, finfo.st_size);
#else
	ssize_t ret = fcopyfile(ifd, ofd, 0, COPYFILE_ALL);
#endif
	close(ifd);
	close(ofd);
	if (ret == -1) {
		ERROR("Cannot copy '%s'->'%s', %s.\n", infile,
		      outfile, strerror(errno));
	}
	return ret;
}

enum futil_file_err futil_open_file(const char *infile, int *fd,
				    enum file_mode mode)
{
	if (mode == FILE_RW) {
		VB2_DEBUG("open RW %s\n", infile);
		*fd = open(infile, O_RDWR);
		if (*fd < 0) {
			ERROR("Can't open %s for writing: %s\n", infile,
			      strerror(errno));
			return FILE_ERR_OPEN;
		}
	} else {
		VB2_DEBUG("open RO %s\n", infile);
		*fd = open(infile, O_RDONLY);
		if (*fd < 0) {
			ERROR("Can't open %s for reading: %s\n", infile,
			      strerror(errno));
			return FILE_ERR_OPEN;
		}
	}
	return FILE_ERR_NONE;
}

enum futil_file_err futil_close_file(int fd)
{
	if (fd >= 0 && close(fd)) {
		ERROR("Closing ifd: %s\n", strerror(errno));
		return FILE_ERR_CLOSE;
	}
	return FILE_ERR_NONE;
}

enum futil_file_err futil_map_file(int fd, enum file_mode mode,
				   uint8_t **buf, uint32_t *len)
{
	struct stat sb;
	void *mmap_ptr;
	uint32_t reasonable_len;

	if (0 != fstat(fd, &sb)) {
		ERROR("Can't stat input file: %s\n", strerror(errno));
		return FILE_ERR_STAT;
	}

#if !defined(HAVE_MACOS) && !defined(__FreeBSD__) && !defined(__OpenBSD__)
	if (S_ISBLK(sb.st_mode))
		ioctl(fd, BLKGETSIZE64, &sb.st_size);
#endif

	/* If the image is larger than 2^32 bytes, it's wrong. */
	if (sb.st_size < 0 || sb.st_size > UINT32_MAX) {
		ERROR("Image size is unreasonable\n");
		return FILE_ERR_SIZE;
	}
	reasonable_len = (uint32_t)sb.st_size;

	if (mode == FILE_RW)
		mmap_ptr = mmap(0, sb.st_size,
				PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	else
		mmap_ptr = mmap(0, sb.st_size,
				PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);

	if (mmap_ptr == MAP_FAILED) {
		ERROR("Can't mmap %s file: %s\n",
		      mode == FILE_RW ? "output" : "input", strerror(errno));
		return FILE_ERR_MMAP;
	}

	*buf = (uint8_t *)mmap_ptr;
	*len = reasonable_len;
	return FILE_ERR_NONE;
}

enum futil_file_err futil_unmap_file(int fd, enum file_mode mode,
				     uint8_t *buf, uint32_t len)
{
	void *mmap_ptr = buf;
	enum futil_file_err err = FILE_ERR_NONE;

	if (mode == FILE_RW &&
	    (0 != msync(mmap_ptr, len, MS_SYNC | MS_INVALIDATE))) {
		ERROR("msync failed: %s\n", strerror(errno));
		err = FILE_ERR_MSYNC;
	}

	if (0 != munmap(mmap_ptr, len)) {
		ERROR("Can't munmap pointer: %s\n", strerror(errno));
		if (err == FILE_ERR_NONE)
			err = FILE_ERR_MUNMAP;
	}

	return err;
}

enum futil_file_err futil_open_and_map_file(const char *infile, int *fd,
					    enum file_mode mode, uint8_t **buf,
					    uint32_t *len)
{
	enum futil_file_err rv = futil_open_file(infile, fd, mode);
	if (rv != FILE_ERR_NONE)
		return rv;

	rv = futil_map_file(*fd, mode,  buf, len);
	if (rv != FILE_ERR_NONE)
		futil_close_file(*fd);

	return rv;
}

enum futil_file_err futil_unmap_and_close_file(int fd, enum file_mode mode,
					       uint8_t *buf, uint32_t len)
{
	enum futil_file_err rv = FILE_ERR_NONE;

	if (buf)
		rv = futil_unmap_file(fd, mode, buf, len);
	if (rv != FILE_ERR_NONE)
		return rv;

	if (fd != -1)
		return futil_close_file(fd);
	else
		return FILE_ERR_NONE;
}

#define DISK_SECTOR_SIZE 512
enum futil_file_type ft_recognize_gpt(uint8_t *buf, uint32_t len)
{
	GptHeader *h;

	/* GPT header starts at sector 1, is one sector long */
	if (len < 2 * DISK_SECTOR_SIZE)
		return FILE_TYPE_UNKNOWN;

	h = (GptHeader *)(buf + DISK_SECTOR_SIZE);

	if (memcmp(h->signature, GPT_HEADER_SIGNATURE,
		   GPT_HEADER_SIGNATURE_SIZE) &&
	    memcmp(h->signature, GPT_HEADER_SIGNATURE2,
		   GPT_HEADER_SIGNATURE_SIZE))
		return FILE_TYPE_UNKNOWN;
	if (h->revision != GPT_HEADER_REVISION)
		return FILE_TYPE_UNKNOWN;
	if (h->size < MIN_SIZE_OF_HEADER || h->size > MAX_SIZE_OF_HEADER)
		return FILE_TYPE_UNKNOWN;

	if (HeaderCrc(h) != h->header_crc32)
		return FILE_TYPE_UNKNOWN;

	return FILE_TYPE_CHROMIUMOS_DISK;
}

void parse_digest_or_die(uint8_t *buf, int len, const char *str)
{
	if (!parse_hash(buf, len, str)) {
		ERROR("Invalid DIGEST \"%s\"\n", str);
		exit(1);
	}
}

void print_bytes(const void *ptr, size_t len)
{
	const uint8_t *buf = (const uint8_t *)ptr;

	for (size_t i = 0; i < len; i++)
		printf("%02x", *buf++);
}

int write_to_file(const char *msg, const char *filename, uint8_t *start,
		  size_t size)
{
	FILE *fp;
	int r = 0;

	fp = fopen(filename, "wb");
	if (!fp) {
		r = errno;
		ERROR("Unable to open %s for writing: %s\n", filename,
		      strerror(r));
		return r;
	}

	/* Don't write zero bytes */
	if (size && 1 != fwrite(start, size, 1, fp)) {
		r = errno;
		ERROR("Unable to write to %s: %s\n", filename, strerror(r));
	}

	if (fclose(fp) != 0) {
		int e = errno;
		ERROR("Unable to close %s: %s\n", filename, strerror(e));
		if (!r)
			r = e;
	}

	if (!r && msg)
		printf("%s %s\n", msg, filename);

	return r;
}
