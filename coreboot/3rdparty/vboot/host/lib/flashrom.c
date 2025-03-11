/* Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/* For strdup */
#define _POSIX_C_SOURCE 200809L

#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "2api.h"
#include "2return_codes.h"
#include "host_misc.h"
#include "flashrom.h"
#include "subprocess.h"

#define FLASHROM_EXEC_NAME "flashrom"

/**
 * Helper to create a temporary file, and optionally write some data
 * into it.
 *
 * @param data		If data needs to be written to the file, a
 *			pointer to the buffer.  Pass NULL to just
 *			create an empty temporary file.
 * @param data_size	The size of the buffer to write, if applicable.
 * @param path_out	An output pointer for the filename.  Caller
 *			should free.
 *
 * @return VB2_SUCCESS on success, or a relevant error.
 */
static vb2_error_t write_temp_file(const uint8_t *data, uint32_t data_size,
				   char **path_out)
{
	int fd;
	ssize_t write_rv;
	vb2_error_t rv;
	char *path;
	mode_t umask_save;

	*path_out = NULL;

	path = strdup(VBOOT_TMP_DIR "/vb2_flashrom.XXXXXX");

	/* Set the umask before mkstemp for security considerations. */
	umask_save = umask(077);
	fd = mkstemp(path);
	umask(umask_save);
	if (fd < 0) {
		rv = VB2_ERROR_WRITE_FILE_OPEN;
		goto fail;
	}

	while (data && data_size > 0) {
		write_rv = write(fd, data, data_size);
		if (write_rv < 0) {
			close(fd);
			unlink(path);
			rv = VB2_ERROR_WRITE_FILE_DATA;
			goto fail;
		}

		data_size -= write_rv;
		data += write_rv;
	}

	close(fd);
	*path_out = path;
	return VB2_SUCCESS;

 fail:
	free(path);
	return rv;
}

static vb2_error_t run_flashrom(const char *const argv[])
{
	int status = subprocess_run(argv, &subprocess_null, &subprocess_null,
				    &subprocess_null);
	if (status) {
		fprintf(stderr, "Flashrom invocation failed (exit status %d):",
			status);

		for (const char *const *argp = argv; *argp; argp++)
			fprintf(stderr, " %s", *argp);

		fprintf(stderr, "\n");
		return VB2_ERROR_FLASHROM;
	}

	return VB2_SUCCESS;
}

vb2_error_t flashrom_read(struct firmware_image *image, const char *region)
{
	char *tmpfile;
	char region_param[PATH_MAX];
	vb2_error_t rv;

	image->data = NULL;
	image->size = 0;

	VB2_TRY(write_temp_file(NULL, 0, &tmpfile));

	if (region)
		snprintf(region_param, sizeof(region_param), "%s:%s", region,
			 tmpfile);

	const char *const argv[] = {
		FLASHROM_EXEC_NAME,
		"-p",
		image->programmer,
		"-r",
		region ? "-i" : tmpfile,
		region ? region_param : NULL,
		NULL,
	};

	rv = run_flashrom(argv);
	if (rv == VB2_SUCCESS)
		rv = vb2_read_file(tmpfile, &image->data, &image->size);

	unlink(tmpfile);
	free(tmpfile);
	return rv;
}

vb2_error_t flashrom_write(struct firmware_image *image, const char *region)
{
	char *tmpfile;
	char region_param[PATH_MAX];
	vb2_error_t rv;

	VB2_TRY(write_temp_file(image->data, image->size, &tmpfile));

	if (region)
		snprintf(region_param, sizeof(region_param), "%s:%s", region,
			 tmpfile);

	const char *const argv[] = {
		FLASHROM_EXEC_NAME,
		"-p",
		image->programmer,
		"--noverify-all",
		"-w",
		region ? "-i" : tmpfile,
		region ? region_param : NULL,
		NULL,
	};

	rv = run_flashrom(argv);
	unlink(tmpfile);
	free(tmpfile);
	return rv;
}
