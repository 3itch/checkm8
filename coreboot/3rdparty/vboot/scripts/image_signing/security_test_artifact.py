#!/usr/bin/env python3
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Run security tests on an artifact"""

import argparse
import os
from pathlib import Path
import subprocess
import sys


DIR = Path(__file__).resolve().parent


def exec_test(name, input, args):
    """Runs a given script

    Args:
        name: the name of the script to execute
        input: the input artifact
        args: list of additional arguments for the script
    """
    # Ensure this script can execute from any directory
    cmd_path = DIR / f"{name}.sh"

    cmd = [cmd_path, input] + args
    ret = subprocess.run(cmd, check=False)
    if ret.returncode:
        sys.exit(ret.returncode)


def get_parser():
    """Creates an argument parser"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--board",
        "-b",
        default="",
        help="Board name",
        type=str,
    )

    parser.add_argument(
        "--config",
        "-c",
        help="Security test baseline config directory",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--input",
        "-i",
        help="Artfact to test",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--keyset-is-mp",
        action="store_true",
        help="Target artifact is signed with a mass production keyset",
        default=False,
    )

    return parser


def main(argv):
    """Main function, parses arguments and invokes the relevant scripts"""
    parser = get_parser()
    opts = parser.parse_args(argv)

    # Run generic baseline tests.
    baseline_tests = [
        "ensure_sane_lsb-release",
    ]

    if opts.keyset_is_mp:
        baseline_tests += [
            "ensure_no_nonrelease_files",
            "ensure_secure_kernelparams",
        ]

    for test in baseline_tests:
        exec_test(
            test, opts.input, [os.path.join(opts.config, f"{test}.config")]
        )

    # Run generic non-baseline tests.
    tests = []

    if opts.keyset_is_mp:
        tests += [
            "ensure_not_ASAN",
            "ensure_not_tainted_license",
            "ensure_update_verification",
        ]

    for test in tests:
        exec_test(test, opts.input, [])

    # Run custom tests.
    if opts.keyset_is_mp:
        # AMD PSP flags only need to be checked for MP-signed artifacts.
        exec_test("ensure_amd_psp_flags", opts.input, [opts.board])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
