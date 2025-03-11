/* Copyright 2011 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Host functions for verified boot.
 */

/* TODO: change all 'return 0', 'return 1' into meaningful return codes */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "host_common.h"

char* StrCopy(char* dest, const char* src, int dest_size)
{
	strncpy(dest, src, dest_size);
	dest[dest_size - 1] = '\0';
	return dest;
}

uint8_t* ReadFile(const char* filename, uint64_t* sizeptr)
{
	FILE* f;
	uint8_t* buf;
	long size;

	f = fopen(filename, "rb");
	if (!f) {
		fprintf(stderr, "Unable to open file %s\n", filename);
		return NULL;
	}

	fseek(f, 0, SEEK_END);
	size = ftell(f);
	if (size < 0) {
		fclose(f);
		return NULL;
	}
	rewind(f);

	buf = malloc(size);
	if (!buf) {
		fclose(f);
		return NULL;
	}

	if (1 != fread(buf, size, 1, f)) {
		fprintf(stderr, "Unable to read from file %s\n", filename);
		fclose(f);
		free(buf);
		return NULL;
	}

	fclose(f);
	if (sizeptr)
		*sizeptr = size;
	return buf;
}

char* ReadFileFirstLine(char* dest, int size, const char* filename)
{
	char* got;
	FILE* f;

	f = fopen(filename, "rt");
	if (!f)
		return NULL;

	got = fgets(dest, size, f);
	fclose(f);

	/* chomp the trailing newline if any */
	if (got)
		dest[strcspn(dest, "\n")] = 0;
	return got;
}

int ReadFileInt(const char* filename, unsigned* value)
{
	char buf[64];
	char* e = NULL;

	if (!ReadFileFirstLine(buf, sizeof(buf), filename))
		return -1;

	/* Convert to integer.  Allow characters after the int ("123 blah"). */
	*value = (unsigned)strtoul(buf, &e, 0);
	if (e == buf)
		return -1;  /* No characters consumed, so conversion failed */

	return 0;
}

int ReadFileBit(const char* filename, int bitmask)
{
	unsigned value;
	if (ReadFileInt(filename, &value) < 0)
		return -1;
	else return (value & bitmask ? 1 : 0);
}

vb2_error_t WriteFile(const char* filename, const void *data, uint64_t size)
{
	FILE *f = fopen(filename, "wb");
	if (!f) {
		fprintf(stderr, "Unable to open file %s\n", filename);
		return 1;
	}

	if (1 != fwrite(data, size, 1, f)) {
		fprintf(stderr, "Unable to write to file %s\n", filename);
		fclose(f);
		unlink(filename);  /* Delete any partial file */
		return 1;
	}

	fclose(f);
	return 0;
}

bool parse_hex(uint8_t *val, const char *str)
{
	uint8_t v = 0;
	char c;
	int digit;

	for (digit = 0; digit < 2; digit++) {
		c = *str;
		if (!c)
			return false;
		if (!isxdigit(c))
			return false;
		c = tolower(c);
		if (c >= '0' && c <= '9')
			v += c - '0';
		else
			v += 10 + c - 'a';
		if (!digit)
			v <<= 4;
		str++;
	}

	*val = v;
	return true;
}

bool parse_hash(uint8_t *buf, size_t len, const char *str)
{
	const char *s = str;
	int i;

	for (i = 0; i < len; i++) {
		/* skip whitespace */
		while (*s && isspace(*s))
			s++;
		if (!*s)
			break;
		if (!parse_hex(buf, s))
			break;

		/* on to the next byte */
		s += 2;
		buf++;
	}

	if (i != len || *s)
		return false;
	return true;
}
