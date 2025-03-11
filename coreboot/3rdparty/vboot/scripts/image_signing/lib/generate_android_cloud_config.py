#!/usr/bin/env python3
# Copyright 2024 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Generates cloud config files to be used by apksigner for signing.

1. Generates base pkcs#11 config file.

Usage: generate_android_cloud_config.py [
       --output_dir <output directory for config file>
       ]
"""

from argparse import ArgumentParser
from argparse import Namespace
import logging
import os
from pathlib import Path
import sys
from typing import Sequence


CONFIG_FILE_NAME = "pkcs11_java.cfg"
PKCS11_MODULE_PATH = "PKCS11_MODULE_PATH"


def _parse_flags(argv: Sequence[str]) -> Namespace:
    """The function passed to absl.app.run to parse flags.

    :param argv: A list of input arguments.

    :return parsed input namespace.
    """
    parser = ArgumentParser(
        description="Generate config files to be used for pkcs#11 signing using gcloud."
    )

    parser.add_argument(
        "--output_dir",
        "-o",
        type=str,
        help="Output directory location where files will be "
        "generated. This would default to input directory "
        "if nothing is provided.",
        default=os.getcwd(),
    )
    return parser.parse_args(argv[1:])


def generate_config_file(output_dir: str) -> None:
    """
    Generates a static config file with name, description, library path and
    slotListIndex.
    """
    config_file_name = os.path.join(output_dir, CONFIG_FILE_NAME)

    try:
        lib_path = os.getenv(PKCS11_MODULE_PATH)
        with open(config_file_name, "w") as file:
            file.write("name = libkmsp11\n")
            file.write("description = Google Cloud KMS PKCS11 Library\n")
            file.write(f"library = {lib_path}\n")
            file.write("slotListIndex = 0\n")
    except OSError as ex:
        logging.error("Unable to open create file due to exception: ", ex)
        sys.exit(1)


def _validate(args: Namespace) -> str:
    lib_path = os.getenv(PKCS11_MODULE_PATH)
    if not lib_path:
        logging.error("Please set PKCS11_MODULE_PATH before continuing.")
        sys.exit(1)

    return args.output_dir


def main(argv) -> None:
    args = _parse_flags(argv)
    output_dir = _validate(args)

    # Generate the pkcs11 config file.
    generate_config_file(output_dir=output_dir)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
