% FUTILITY(1) Version 1.0 | Unified Firmware Utility Program

[TOC]

NAME
============

**futility** - Futility is a unified firmware tool that provides a variety of
firmware peripheral functions and subcommands.

SYNOPSIS
========

- **futility** \[options] COMMAND \[args...]
- **futility** **help** COMMAND

DESCRIPTION
===========

This is the unified firmware utility, which contains various of distinct verified
boot tools as subcommands.

Options
-------

### Global Options:

\--vb1

:   Use only vboot v1.0 binary formats.

\--vb21

:   Use only vboot v2.1 binary formats.

\--debug

:   Be noisy about what's going on.


### Commands

create

:   Create a keypair from an RSA .pem file.

dump_fmap

:   Display FMAP contents from a firmware image.

dump_kernel_config

:   Prints the kernel command line.

flash

:   Manage AP SPI flash properties and writeprotect configuration.

gbb, gbb_utility

:   Manipulate the Google Binary Block (GBB).
    See [cmd_gbb_utility](./docs/cmd_gbb_utility.md) for detailed information.

    Examples:

        futility gbb --get $FILE
        (dut) futility gbb --get --flash
        (host) futility gbb --get --servo
        (host) futility gbb --set --flags=$FLAGS --servo

gscvd

:   Create RO verification structure.

help

:   Show a bit of help.

load_fmap

:   Replace the contents of specified FMAP areas.

pcr

:   Simulate a TPM PCR extension operation.

read

:   Read AP firmware.

    Examples:

        (dut) futility read $IMG_OUT
        (host) futility read --servo $IMG_OUT
        (host) futility read --ccd_without_servod -r RO_VPD $IMG_OUT

show

:   Display the content of various binary components.

sign

:   Sign / resign various binary components.

update

:   Update system firmware.

    Examples:

        (dut) futility update -i $IMG
        (host) futility update --wp 0 -i $IMG --servo
        (host) futility update --force -i $IMG --servo

vbutil_firmware

:   Verified boot firmware utility.

vbutil_kernel

:   Creates, signs, and verifies the kernel partition.

vbutil_key

:   Wraps RSA keys with vboot headers.

vbutil_keyblock

:   Creates, signs, and verifies a keyblock.

verify

:   Verify the signatures of various binary components. This does not verify GSCVD contents.

version

:   Show the futility source revision and build date.
