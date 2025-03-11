/* Copyright 2013 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "futility.h"

const char *ft_print_header = NULL;
const char *ft_print_header2 = NULL;

/******************************************************************************/

static const char *const usage = "\n"
"Usage: " MYNAME " [options] COMMAND [args...]\n"
"\n"
"This is the unified firmware utility, which contains various of distinct\n"
"verified boot tools as subcommands.\n"
"\n"
"See the README file for more information about the available commands\n";

static const char *const options =
"Global options:\n"
"\n"
"  --vb1        Use only vboot v1.0 binary formats\n"
"  --vb21       Use only vboot v2.1 binary formats\n"
"  --debug      Be noisy about what's going on\n"
"\n";

static const struct futil_cmd_t *find_command(const char *name)
{
	const struct futil_cmd_t *const *cmd;

	for (cmd = futil_cmds; *cmd; cmd++)
		if (((*cmd)->version & vboot_version) &&
		    !strcmp((*cmd)->name, name))
			return *cmd;

	return NULL;
}

static void list_commands(void)
{
	const struct futil_cmd_t *const *cmd;

	for (cmd = futil_cmds; *cmd; cmd++)
		if (vboot_version & (*cmd)->version)
			printf("  %-20s %s\n",
			       (*cmd)->name, (*cmd)->shorthelp);
}

static int run_command(const struct futil_cmd_t *cmd, int argc, char *argv[])
{
	int i;
	VB2_DEBUG("\"%s\" ...\n", cmd->name);
	for (i = 0; i < argc; i++)
		VB2_DEBUG("  argv[%d] = \"%s\"\n", i, argv[i]);

	return cmd->handler(argc, argv);
}

static int do_help(int argc, char *argv[])
{
	const struct futil_cmd_t *cmd;
	const char *vstr = "";

	/* Help about a known command? */
	if (argc > 1) {
		cmd = find_command(argv[1]);
		if (cmd) {
			/* Let the command provide its own help */
			argv[0] = argv[1];
			argv[1] = (char *)"--help";
			return run_command(cmd, argc, argv);
		}
	}

	fputs(usage, stdout);

	if (vboot_version == VBOOT_VERSION_ALL)
		fputs(options, stdout);

	switch (vboot_version) {
	case VBOOT_VERSION_1_0:
		vstr = "version 1.0 ";
		break;
	case VBOOT_VERSION_2_1:
		vstr = "version 2.1 ";
		break;
	case VBOOT_VERSION_ALL:
		vstr = "";
		break;
	}
	printf("The following %scommands are built-in:\n\n", vstr);
	list_commands();
	printf("\nUse \"" MYNAME " help COMMAND\" for more information.\n\n");

	return 0;
}

DECLARE_FUTIL_COMMAND(help, do_help, VBOOT_VERSION_ALL,
		      "Show a bit of help (you're looking at it)");

static const char ver_help[] =
	"Show the futility source revision and build date";
static int do_version(int argc, char *argv[])
{
	if (argc > 1)
		printf("%s - %s\n", argv[0], ver_help);
	else
		printf("%s\n", futility_version);
	return 0;
}

DECLARE_FUTIL_COMMAND(version, do_version, VBOOT_VERSION_ALL,
		      ver_help);

static char *simple_basename(char *str)
{
	char *s = strrchr(str, '/');
	if (s)
		s++;
	else
		s = str;
	return s;
}

/* Here we go */
#define OPT_HELP 1000
test_mockable
int main(int argc, char *argv[], char *envp[])
{
	char *progname;
	const struct futil_cmd_t *cmd;
	int i, errorcnt = 0;
	int vb_ver = VBOOT_VERSION_ALL;
	int helpind = 0;
	struct option long_opts[] = {
		{"debug", 0, &debugging_enabled, 1},
		{"vb1" ,  0, &vb_ver, VBOOT_VERSION_1_0},
		{"vb21",  0, &vb_ver, VBOOT_VERSION_2_1},
		{"help",  0, 0, OPT_HELP},
		{ 0, 0, 0, 0},
	};

	/* How were we invoked? */
	progname = simple_basename(argv[0]);

	/* See if the program name is a command we recognize */
	cmd = find_command(progname);
	if (cmd) {
		/* Yep, just do that */
		return !!run_command(cmd, argc, argv);
	}

	/* Parse the global options, stopping at the first non-option. */
	opterr = 0;				/* quiet, you. */
	while ((i = getopt_long(argc, argv, "+:", long_opts, NULL)) != -1) {
		switch (i) {
		case OPT_HELP:
			/* Remember where we found this option */
			/* Note: this might be GNU-specific */
			helpind = optind - 1;
			break;
		case '?':
			if (optopt)
				fprintf(stderr, "Unrecognized option: -%c\n",
					optopt);
			else
				fprintf(stderr, "Unrecognized option: %s\n",
					argv[optind - 1]);
			errorcnt++;
			break;
		case ':':
			fprintf(stderr, "Missing argument to -%c\n", optopt);
			errorcnt++;
			break;
		case 0:				/* handled option */
			break;
		default:
			FATAL("Unrecognized getopt output: %d\n", i);
		}
	}
	vboot_version = vb_ver;

	/*
	 * Translate "--help" in the args to "help" as the first parameter,
	 * by rearranging argv[].
	 */
	if (helpind) {
		int j;
		optind--;
		for (j = helpind; j < optind; j++)
			argv[j] = argv[j + 1];
		argv[j] = (char *)"help";
	}

	/* We require a command name. */
	if (errorcnt || argc == optind) {
		do_help(1, argv);
		return 1;
	}

	/* For reasons I've forgotten, treat /blah/blah/CMD the same as CMD */
	argv[optind] = simple_basename(argv[optind]);

	/* Do we recognize the command? */
	cmd = find_command(argv[optind]);
	if (cmd) {
		/* Reset so commands can parse their own options */
		argc -= optind;
		argv += optind;
		optind = 0;
		return !!run_command(cmd, argc, argv);
	}

	/* Nope. We've no clue what we're being asked to do. */
	do_help(1, argv);
	return 1;
}
