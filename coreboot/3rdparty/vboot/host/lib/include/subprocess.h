/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Library for creating subprocesses in a high level manner.
 */

#ifndef VBOOT_REFERENCE_SUBPROCESS_H_
#define VBOOT_REFERENCE_SUBPROCESS_H_

#include <stdio.h>
#include <stdlib.h>

/**
 * subprocess_target is the "mini language" of the subprocess
 * library. It describes where to read or write data from the process.
 *
 * There are currently five target of targets:
 *
 * - TARGET_NULL: /dev/null, no need to describe any other fields.
 *
 * - TARGET_FD: file descriptor, put the fd in the fd field.
 *
 * - TARGET_FILE: FILE *, put the FILE pointer in the file field.
 *
 * - TARGET_BUFFER: read to, or write from, a buffer. Fields:
 *   - buffer->buf: the buffer
 *   - buffer->size: the size of that buffer
 *   - buffer->bytes_consumed: do not fill out this field.
 *     subprocess_run will set it to the number of bytes read from the
 *     process (if writing to a buffer). Goes unused when reading from
 *     a buffer.
 *
 * - TARGET_BUFFER_NULL_TERMINATED: when reading from a buffer, don't
 *   fill out the size field and subprocess_run will strlen for you.
 *   When writing to a buffer, subprocess_run will reserve one byte of
 *   the size for a null terminator and guarantee that the output is
 *   always NULL terminated.
 *
 * - TARGET_CALLBACK: when the target is provided as an input to a
 *   process, the callback will be called occasionally to provide
 *   input to the process. The callback should fill buf with up to
 *   buf_sz bytes of data, and return the number of bytes
 *   written, or negative values on error. When the target is provided
 *   as an output to a process, the callback will be called
 *   occasionally with buf_sz bytes of data from the output put into
 *   buf. In this case, the return value from the callback is
 *   ignored except for errors. The data field is for application use
 *   and will always be passed to the data parameter of the callback
 *   function.
 */
struct subprocess_target {
	enum {
		TARGET_NULL,
		TARGET_FD,
		TARGET_FILE,
		TARGET_BUFFER,
		TARGET_BUFFER_NULL_TERMINATED,
		TARGET_CALLBACK,
	} type;
	union {
		int fd;
		FILE *file;
		struct {
			char *buf;
			size_t size;

			/*
			 * This variable is the output of the number of bytes
			 * read or written. It should be read by the caller, not
			 * set.
			 */
			size_t bytes_consumed;
		} buffer;
		struct {
			ssize_t (*cb)(char *buf, size_t buf_sz, void *data);
			void *data;
		} callback;
	};
	struct {
		int pipefd[2];
	} priv;
};

/**
 * A convenience subprocess target which uses TARGET_NULL.
 */
extern struct subprocess_target subprocess_null;

/**
 * A convenience subprocess target which uses TARGET_FD to STDIN_FILENO.
 */
extern struct subprocess_target subprocess_stdin;

/**
 * A convenience subprocess target which uses TARGET_FD to STDOUT_FILENO.
 */
extern struct subprocess_target subprocess_stdout;

/**
 * A convenience subprocess target which uses TARGET_FD to STDERR_FILENO.
 */
extern struct subprocess_target subprocess_stderr;

/**
 * Call a process and run until completion.
 *
 * @param argv          A NULL-terminated list of arguments describing
 *                      the program to run.
 * @param input         The subprocess_target connected to stdin.
 * @param output        The subprocess_target connected to stdout.
 * @param error         The subprocess_target connected to stderr.
 *
 * If either input, output, or error are set to NULL, they will be
 * &subprocess_stdin, &subprocess_stdout, or &subprocess_stderr
 * respectively.
 *
 * @return The exit status on success, or negative values on error.
 */
int subprocess_run(const char *const argv[],
		   struct subprocess_target *input,
		   struct subprocess_target *output,
		   struct subprocess_target *error);

#endif  /* VBOOT_REFERENCE_SUBPROCESS_H_ */
