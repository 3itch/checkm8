/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "2common.h"
#include "subprocess.h"

#define MAX_CB_BUF_SIZE 2048

static int init_target_private(struct subprocess_target *target)
{
	switch (target->type) {
	case TARGET_BUFFER:
	case TARGET_BUFFER_NULL_TERMINATED:
	case TARGET_CALLBACK:
		return pipe(target->priv.pipefd);
	default:
		return 0;
	}
}

static int flags_for_fd(int fd)
{
	switch (fd) {
	case STDIN_FILENO:
		return O_RDONLY;
	case STDOUT_FILENO:
	case STDERR_FILENO:
		return O_WRONLY;
	default:
		return -1;
	}
}

static int connect_process_target(struct subprocess_target *target, int fd)
{
	int target_fd;

	switch (target->type) {
	case TARGET_NULL:
		target_fd = open("/dev/null", flags_for_fd(fd));
		break;
	case TARGET_FD:
		target_fd = target->fd;
		break;
	case TARGET_FILE:
		target_fd = fileno(target->file);
		break;
	case TARGET_BUFFER:
	case TARGET_BUFFER_NULL_TERMINATED:
	case TARGET_CALLBACK:
		switch (fd) {
		case STDIN_FILENO:
			target_fd = target->priv.pipefd[0];
			close(target->priv.pipefd[1]);
			break;
		case STDOUT_FILENO:
		case STDERR_FILENO:
			target_fd = target->priv.pipefd[1];
			close(target->priv.pipefd[0]);
			break;
		default:
			return -1;
		}
		break;
	default:
		return -1;
	}

	return dup2(target_fd, fd);
}

static int process_target_input_buffer(struct subprocess_target *target)
{
	ssize_t write_rv;
	size_t bytes_to_write;
	char *buf;

	switch (target->type) {
	case TARGET_BUFFER:
		bytes_to_write = target->buffer.size;
		break;
	case TARGET_BUFFER_NULL_TERMINATED:
		bytes_to_write = strlen(target->buffer.buf);
		break;
	default:
		return -1;
	}

	buf = target->buffer.buf;
	while (bytes_to_write) {
		write_rv = write(target->priv.pipefd[1], buf, bytes_to_write);
		if (write_rv <= 0)
			return -1;
		buf += write_rv;
		bytes_to_write -= write_rv;
	}

	return 0;
}

static int process_target_input_cb(struct subprocess_target *target)
{
	ssize_t write_rv, bytes_to_write;
	char buf[MAX_CB_BUF_SIZE];
	char *bufptr;

	for (;;) {
		bytes_to_write = target->callback.cb(buf, MAX_CB_BUF_SIZE,
						     target->callback.data);
		if (bytes_to_write < 0 || bytes_to_write > MAX_CB_BUF_SIZE)
			return -1;
		if (bytes_to_write == 0)
			return 0;

		bufptr = buf;
		while (bytes_to_write) {
			write_rv = write(target->priv.pipefd[1], bufptr,
					 bytes_to_write);
			if (write_rv <= 0)
				return -1;
			bufptr += write_rv;
			bytes_to_write -= write_rv;
		}
	}
}

static int process_target_input(struct subprocess_target *target)
{
	int rv;

	switch (target->type) {
	case TARGET_BUFFER:
	case TARGET_BUFFER_NULL_TERMINATED:
	case TARGET_CALLBACK:
		break;
	default:
		return 0;
	}

	close(target->priv.pipefd[0]);
	switch (target->type) {
	case TARGET_BUFFER:
	case TARGET_BUFFER_NULL_TERMINATED:
		rv = process_target_input_buffer(target);
		break;
	case TARGET_CALLBACK:
		rv = process_target_input_cb(target);
		break;
	default:
		return -1;
	}

	close(target->priv.pipefd[1]);
	return rv;
}

static int process_target_output_buffer(struct subprocess_target *target)
{
	ssize_t read_rv;
	size_t bytes_remaining;

	switch (target->type) {
	case TARGET_BUFFER:
		bytes_remaining = target->buffer.size;
		break;
	case TARGET_BUFFER_NULL_TERMINATED:
		if (target->buffer.size == 0)
			return -1;
		bytes_remaining = target->buffer.size - 1;
		break;
	default:
		return 0;
	}

	target->buffer.bytes_consumed = 0;
	while (bytes_remaining) {
		read_rv = read(
			target->priv.pipefd[0],
			target->buffer.buf + target->buffer.bytes_consumed,
			bytes_remaining);
		if (read_rv < 0)
			return -1;
		if (read_rv == 0)
			break;
		target->buffer.bytes_consumed += read_rv;
		bytes_remaining -= read_rv;
	}

	if (target->type == TARGET_BUFFER_NULL_TERMINATED)
		target->buffer.buf[target->buffer.bytes_consumed] = '\0';
	return 0;
}

static int process_target_output_cb(struct subprocess_target *target)
{
	char buf[MAX_CB_BUF_SIZE];
	ssize_t rv;

	for (;;) {
		rv = read(target->priv.pipefd[0], buf, MAX_CB_BUF_SIZE);
		if (rv < 0)
			return -1;
		if (rv == 0)
			break;
		if (target->callback.cb(buf, rv, target->callback.data) < 0)
			return -1;
	}

	return 0;
}

static int process_target_output(struct subprocess_target *target)
{
	int rv;

	switch (target->type) {
	case TARGET_BUFFER:
	case TARGET_BUFFER_NULL_TERMINATED:
	case TARGET_CALLBACK:
		break;
	default:
		return 0;
	}

	close(target->priv.pipefd[1]);
	switch (target->type) {
	case TARGET_BUFFER:
	case TARGET_BUFFER_NULL_TERMINATED:
		rv = process_target_output_buffer(target);
		break;
	case TARGET_CALLBACK:
		rv = process_target_output_cb(target);
		break;
	default:
		return -1;
	}

	close(target->priv.pipefd[0]);
	return rv;
}

static bool contains_spaces(const char *s)
{
	for (size_t i = 0; s[i]; i++) {
		if (isspace(s[i]))
			return true;
	}
	return false;
}

static void subprocess_log_call(const char *const argv[])
{
	VB2_DEBUG("Run:");

	for (size_t i = 0; argv[i]; i++) {
		if (contains_spaces(argv[i]))
			VB2_DEBUG_RAW(" '%s'", argv[i]);
		else
			VB2_DEBUG_RAW(" %s", argv[i]);
	}
	VB2_DEBUG_RAW("\n");
}

struct subprocess_target subprocess_null = {
	.type = TARGET_NULL,
};

struct subprocess_target subprocess_stdin = {
	.type = TARGET_FD,
	.fd = STDIN_FILENO,
};

struct subprocess_target subprocess_stdout = {
	.type = TARGET_FD,
	.fd = STDOUT_FILENO,
};

struct subprocess_target subprocess_stderr = {
	.type = TARGET_FD,
	.fd = STDERR_FILENO,
};

test_mockable
int subprocess_run(const char *const argv[],
		   struct subprocess_target *input,
		   struct subprocess_target *output,
		   struct subprocess_target *error)
{
	int status;
	pid_t pid = -1;

	subprocess_log_call(argv);

	if (!input)
		input = &subprocess_stdin;
	if (!output)
		output = &subprocess_stdout;
	if (!error)
		error = &subprocess_stderr;

	if (init_target_private(input) < 0)
		goto fail;
	if (init_target_private(output) < 0)
		goto fail;
	if (init_target_private(error) < 0)
		goto fail;

	if ((pid = fork()) < 0)
		goto fail;
	if (pid == 0) {
		/* Child process */
		if (connect_process_target(input, STDIN_FILENO) < 0)
			goto fail;
		if (connect_process_target(output, STDOUT_FILENO) < 0)
			goto fail;
		if (connect_process_target(error, STDERR_FILENO) < 0)
			goto fail;
		execvp(*argv, (char *const *)argv);
		goto fail;
	}

	/* Parent process */
	if (process_target_input(input) < 0)
		goto fail;
	if (process_target_output(output) < 0)
		goto fail;
	if (process_target_output(error) < 0)
		goto fail;

	if (waitpid(pid, &status, 0) < 0)
		goto fail;

	if (WIFEXITED(status))
		return WEXITSTATUS(status);

 fail:
	VB2_DEBUG("Failed to execute external command: %s\n", strerror(errno));
	if (pid == 0)
		exit(127);
	return -1;
}
