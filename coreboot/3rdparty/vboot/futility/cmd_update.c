/* Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * The command line tool to invoke firmware updater.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "futility.h"
#include "updater.h"

#ifdef USE_FLASHROM

enum {
	OPT_DUMMY = 0x1000,
	OPT_DETECT_MODEL_ONLY,
	OPT_FACTORY,
	OPT_FAST,
	OPT_FORCE,
	OPT_GBB_FLAGS,
	OPT_HOST_ONLY,
	OPT_MANIFEST,
	OPT_PARSEABLE_MANIFEST,
	OPT_MODEL,
	OPT_OUTPUT_DIR,
	OPT_QUIRKS,
	OPT_QUIRKS_LIST,
	OPT_REPACK,
	OPT_SERVO_NORESET,
	OPT_SIGNATURE,
	OPT_SYS_PROPS,
	OPT_UNLOCK_ME,
	OPT_UNPACK,
	OPT_WRITE_PROTECTION,
};

/* Command line options */
static struct option const long_opts[] = {
	SHARED_FLASH_ARGS_LONGOPTS
	/* name  has_arg *flag val */
	{"help", 0, NULL, 'h'},
	{"debug", 0, NULL, 'd'},
	{"verbose", 0, NULL, 'v'},

	{"image", 1, NULL, 'i'},
	{"ec_image", 1, NULL, 'e'},
	{"try", 0, NULL, 't'},
	{"archive", 1, NULL, 'a'},
	{"mode", 1, NULL, 'm'},

	{"detect-model-only", 0, NULL, OPT_DETECT_MODEL_ONLY},
	{"factory", 0, NULL, OPT_FACTORY},
	{"fast", 0, NULL, OPT_FAST},
	{"force", 0, NULL, OPT_FORCE},
	{"gbb_flags", 1, NULL, OPT_GBB_FLAGS},
	{"host_only", 0, NULL, OPT_HOST_ONLY},
	{"quirks", 1, NULL, OPT_QUIRKS},
	{"list-quirks", 0, NULL, OPT_QUIRKS_LIST},
	{"manifest", 0, NULL, OPT_MANIFEST},
	{"parseable-manifest", 0, NULL, OPT_PARSEABLE_MANIFEST},
	{"model", 1, NULL, OPT_MODEL},
	{"output_dir", 1, NULL, OPT_OUTPUT_DIR},
	{"repack", 1, NULL, OPT_REPACK},
	{"signature_id", 1, NULL, OPT_SIGNATURE},
	{"sys_props", 1, NULL, OPT_SYS_PROPS},
	{"unlock_me", 0, NULL, OPT_UNLOCK_ME},
	{"unpack", 1, NULL, OPT_UNPACK},
	{"wp", 1, NULL, OPT_WRITE_PROTECTION},

	/* TODO(hungte) Remove following deprecated options. */
	{"noupdate_ec", 0, NULL, OPT_HOST_ONLY},
	{"nocheck_keys", 0, NULL, OPT_FORCE},
	{"update_main", 0, NULL, OPT_DUMMY},
	{"update_ec", 0, NULL, OPT_DUMMY},
	{"check_keys", 0, NULL, OPT_DUMMY},

	{NULL, 0, NULL, 0},
};

static const char *const short_opts =
	"hdvi:e:ta:m:" SHARED_FLASH_ARGS_SHORTOPTS;

static void print_help(int argc, char *argv[])
{
	printf("\n"
		"Usage:  " MYNAME " %s [OPTIONS]\n"
		"\n"
		"Updates firmware in one of the following modes (default to recovery):\n"
		"  autoupdate:\tUpdate RW[A|B], or recovery if RO changed.\n"
		"  recovery:  \tUpdate RW[A&B], (RO, RO:GBB[keys] - if RO changed)\n"
		"  factory:   \tUpdate RW[A&B],  RO, RO:GBB[keys,flags]\n"
		"\n"
		"Note: firmware sections with PRESERVE flags like VPD and\n"
		"      HWID in GBB are always preserved.\n"
		"      GBB flags are preserved in autoupdate and recovery modes.\n"
		"\n"
		"OPTIONS:\n"
		"\n"
		"-i, --image=FILE    \tAP (host) firmware image (image.bin)\n"
		"-e, --ec_image=FILE \tEC firmware image (i.e, ec.bin)\n"
		"-t, --try           \tTry A/B update on reboot if possible\n"
		"-a, --archive=PATH  \tRead resources from archive\n"
		"    --unpack=DIR    \tExtracts archive to DIR\n"
		"    --fast          \tReduce read cycles and do not verify\n"
		"    --quirks=LIST   \tSpecify the quirks to apply\n"
		"    --list-quirks   \tPrint all available quirks\n"
		"-m, --mode=MODE     \tRun updater in the specified mode\n"
		"    --manifest      \tScan the archive to print a manifest in JSON\n"
		"    --parseable-manifest\n"
		"                    \tScan the archive to print a manifest\n"
		"                    \tin shell-parseable format\n"
		SHARED_FLASH_ARGS_HELP
		"\n"
		" * Option --manifest requires either -a,--archive or -i,--image\n"
		"   With -i,--image additional images are accepted with options\n"
		"   -e,--ec_image.\n"
		" * If both --manifest and --fast are specified, the updater\n"
		"   will not scan the archive and simply dump the previously\n"
		"   cached manifest (may be out-dated) from the archive.\n"
		"   Works only with -a,--archive option.\n"
		" * Use of -p,--programmer with option other than '%s',\n"
		"   or with --ccd effectively disables ability to update EC\n"
		"   firmware images.\n"
		" * Emulation works only with the AP (host) firmware image, and\n"
		"   does not support the EC firmware image.\n"
		" * Model detection with option --detect-model-only requires\n"
		"   archive path -a,--archive\n"
		" * The --quirks provides a set of options to override the\n"
		"   default behavior. Run --list-quirks to get the options,\n"
		"   and --quirks OPTION to turn on. To disable a quirk that\n"
		"   was default turned on from the firmware image CBFS, do\n"
		"   --quirks OPTION=0 to turn off.\n"
		"\n"
		"Legacy and compatibility options:\n"
		"    --factory       \tAlias for --mode=factory\n"
		"    --force         \tForce update (skip checking contents)\n"
		"    --output_dir=DIR\tSpecify the target for --mode=output\n"
		"    --unlock_me     \t(deprecated) Unlock the Intel ME before flashing\n"
		"    --signature_id=S\t(deprecated) Same as --model\n"
		"\n"
		"Debugging and testing options:\n"
		"    --wp=1|0        \tSpecify write protection status\n"
		"    --host_only     \tUpdate only AP (host) firmware\n"
		"    --model=MODEL   \tOverride system model for images\n"
		"    --detect-model-only\tDetect model by reading the FRID and exit\n"
		"    --gbb_flags=FLAG\tOverride new GBB flags\n"
		"    --sys_props=LIST\tList of system properties to override\n"
		"-d, --debug         \tPrint debugging messages\n"
		"-v, --verbose       \tPrint verbose messages\n"
		"",
		argv[0], FLASHROM_PROGRAMMER_INTERNAL_AP);
}

static int do_update(int argc, char *argv[])
{
	struct updater_config_arguments args = {0};
	int i, errorcnt = 0;
	const char *prepare_ctrl_name = NULL;
	char *servo_programmer = NULL;
	char *endptr;
	const char *sig = NULL;

	struct updater_config *cfg = updater_new_config();
	assert(cfg);

	opterr = 0;
	while ((i = getopt_long(argc, argv, short_opts, long_opts, 0)) != -1) {
		if (handle_flash_argument(&args, i, optarg))
			continue;
		switch (i) {
		case 'h':
			print_help(argc, argv);
			updater_delete_config(cfg);
			return !!errorcnt;
		case 'd':
			debugging_enabled = 1;
			args.verbosity++;
			break;
		case 'v':
			args.verbosity++;
			break;
		case 'i':
			args.image = optarg;
			break;
		case 'e':
			args.ec_image = optarg;
			break;
		case 't':
			args.try_update = 1;
			break;
		case 'a':
			args.archive = optarg;
			break;
		case 'm':
			args.mode = optarg;
			break;

		case OPT_REPACK:
			args.repack = optarg;
			ERROR("Sorry, --repack is only for the script.\n");
			errorcnt ++;
			break;
		case OPT_UNPACK:
			args.unpack = optarg;
			break;
		case OPT_UNLOCK_ME:
			WARN("--unlock_me will be deprecated by --quirks unlock_csme.\n");
			args.unlock_me = true;
			break;
		case OPT_QUIRKS:
			args.quirks = optarg;
			break;
		case OPT_QUIRKS_LIST:
			updater_list_config_quirks(cfg);
			updater_delete_config(cfg);
			return 0;
		case OPT_OUTPUT_DIR:
			args.output_dir = optarg;
			break;
		case OPT_MODEL:
			if (sig) {
				WARN("Ignore --model=%s because --signature_id=%s is already specified.\n", optarg, sig);
			} else {
				args.model = optarg;
			}
			break;
		case OPT_SIGNATURE:
			WARN("--signature_id is deprecated by --model. "
			      "Please change to `--model=%s` in future.\n",
			      optarg);
			sig = optarg;
			args.model = optarg;
			break;
		case OPT_DETECT_MODEL_ONLY:
			args.detect_model_only = true;
			break;
		case OPT_WRITE_PROTECTION:
			args.write_protection = optarg;
			break;
		case OPT_SYS_PROPS:
			args.sys_props = optarg;
			break;
		case OPT_MANIFEST:
			args.do_manifest = 1;
			args.manifest_format = MANIFEST_PRINT_FORMAT_JSON;
			break;
		case OPT_PARSEABLE_MANIFEST:
			args.do_manifest = 1;
			args.manifest_format = MANIFEST_PRINT_FORMAT_PARSEABLE;
			break;
		case OPT_FACTORY:
			args.is_factory = 1;
			break;
		case OPT_HOST_ONLY:
			args.host_only = 1;
			break;
		case OPT_FORCE:
			args.force_update = 1;
			break;
		case OPT_FAST:
			args.fast_update = 1;
			break;
		case OPT_GBB_FLAGS:
			args.gbb_flags = strtoul(optarg, &endptr, 0);
			if (*endptr) {
				ERROR("Invalid flags: %s\n", optarg);
				errorcnt++;
			} else {
				args.override_gbb_flags = 1;
			}
			break;
		case OPT_DUMMY:
			break;

		case '?':
			errorcnt++;
			if (optopt)
				ERROR("Unrecognized option: -%c\n", optopt);
			else if (argv[optind - 1])
				ERROR("Unrecognized option (possibly '%s')\n",
				      argv[optind - 1]);
			else
				ERROR("Unrecognized option.\n");
			break;
		default:
			errorcnt++;
			ERROR("Failed parsing options.\n");
		}
	}
	if (optind < argc) {
		errorcnt++;
		ERROR("Unexpected arguments.\n");
	}

	if (!errorcnt && args.detect_servo) {
		servo_programmer = host_detect_servo(&prepare_ctrl_name);

		if (!servo_programmer)
			errorcnt++;
		else if (!args.programmer)
			args.programmer = servo_programmer;
	}
	/*
	 * Some boards may need to fetch firmware before starting to
	 * update (i.e., in updater_setup_config) so we want to turn on
	 * cpu_fw_spi mode now.
	 */
	prepare_servo_control(prepare_ctrl_name, true);

	const bool update_needed = updater_should_update(&args);
	if (!errorcnt)
		errorcnt += updater_setup_config(cfg, &args);
	if (!errorcnt && update_needed) {
		int r;
		STATUS("Starting firmware updater.\n");
		r = update_firmware(cfg);
		if (r != UPDATE_ERR_DONE) {
			r = VB2_MIN(r, UPDATE_ERR_UNKNOWN);
			ERROR("%s\n", updater_error_messages[r]);
			errorcnt++;
		}
		/* Use stdout for the final result. */
		printf(">> %s: Firmware updater %s.\n",
			errorcnt ? "FAILED": "DONE",
			errorcnt ? "aborted" : "exits successfully");
	}

	prepare_servo_control(prepare_ctrl_name, false);
	free(servo_programmer);

	updater_delete_config(cfg);
	return !!errorcnt;
}
#define CMD_HELP_STR "Update system firmware"

#else /* USE_FLASHROM */

static int do_update(int argc, char *argv[])
{
	FATAL(MYNAME " was built without flashrom support, `update` command unavailable!\n");
	return -1;
}
#define CMD_HELP_STR "Update system firmware (unavailable in this build)"

#endif /* !USE_FLASHROM */

DECLARE_FUTIL_COMMAND(update, do_update, VBOOT_VERSION_ALL, CMD_HELP_STR);
