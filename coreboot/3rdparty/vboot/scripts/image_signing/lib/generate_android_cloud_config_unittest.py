#!/usr/bin/env python3
# Copyright 2024 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Tests for generate_android_cloud_config.py.

This is run as part of `make runtests`, or `make runtestscripts` if you
want something a little faster.
"""

import os
import unittest

from generate_android_cloud_config import _parse_flags
from generate_android_cloud_config import _validate
from generate_android_cloud_config import PKCS11_MODULE_PATH


PKCS11_TEST_PATH = "test_path"


class Test(unittest.TestCase):
    """Basic unit test cases for generate_android_cloud_config.py"""

    def test_input_args_default(self):
        """Test default input arguments"""
        args = _parse_flags([""])
        self.assertEqual(args.output_dir, os.getcwd())

    def test_validate_missing_pkcs11_module_path(self):
        with self.assertRaises(SystemExit):
            output_dir = _validate(_parse_flags([""]))


if __name__ == "__main__":
    unittest.main()
