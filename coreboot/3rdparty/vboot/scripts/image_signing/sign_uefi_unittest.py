#!/usr/bin/env python3
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Tests for sign_uefi.py.

This is run as part of `make runtests`, or `make runtestscripts` if you
want something a little faster.
"""

from pathlib import Path
import tempfile
import unittest
from unittest import mock

import sign_uefi


class TestSign(unittest.TestCase):
    """Test signing functions in sign_uefi.py."""

    def setUp(self):
        # pylint: disable=consider-using-with
        self.tempdir = tempfile.TemporaryDirectory()
        tempdir = Path(self.tempdir.name)

        # Get key paths.
        self.keys = sign_uefi.Keys(
            private_key=tempdir / "private_key.rsa",
            sign_cert=tempdir / "sign_cert.pem",
            verify_cert=tempdir / "verify_cert.pem",
            kernel_subkey_vbpubk=tempdir / "kernel_subkey.vbpubk",
            crdyshim_private_key=tempdir / "crdyshim.priv.pem",
        )

        # Get target paths.
        self.target_dir = tempdir / "boot"
        self.syslinux_dir = self.target_dir / "syslinux"
        self.efi_boot_dir = self.target_dir / "efi/boot"

        # Make test dirs.
        self.syslinux_dir.mkdir(parents=True)
        self.efi_boot_dir.mkdir(parents=True)

        # Make key files.
        (self.keys.private_key).touch()
        (self.keys.sign_cert).touch()
        (self.keys.verify_cert).touch()
        (self.keys.kernel_subkey_vbpubk).touch()
        (self.keys.crdyshim_private_key).touch()

        # Make EFI files.
        (self.efi_boot_dir / "bootia32.efi").touch()
        (self.efi_boot_dir / "bootx64.efi").touch()
        (self.efi_boot_dir / "testia32.efi").touch()
        (self.efi_boot_dir / "testx64.efi").touch()
        (self.efi_boot_dir / "crdybootia32.efi").touch()
        (self.efi_boot_dir / "crdybootx64.efi").touch()
        (self.syslinux_dir / "vmlinuz.A").touch()
        (self.syslinux_dir / "vmlinuz.B").touch()
        (self.target_dir / "vmlinuz-5.10.156").touch()
        (self.target_dir / "vmlinuz").symlink_to(
            self.target_dir / "vmlinuz-5.10.156"
        )

    def tearDown(self):
        self.tempdir.cleanup()

    @mock.patch("sign_uefi.inject_vbpubk")
    @mock.patch.object(sign_uefi.Signer, "create_detached_signature")
    @mock.patch.object(sign_uefi.Signer, "sign_efi_file")
    def test_sign_target_dir(
        self, mock_sign, mock_detached_sig, mock_inject_vbpubk
    ):
        # Set an EFI glob that matches only some of the EFI files.
        efi_glob = "test*.efi"

        # Sign, but with the actual signing mocked out.
        sign_uefi.sign_target_dir(self.target_dir, self.keys, efi_glob)

        # Check that the correct list of files got signed.
        self.assertEqual(
            mock_sign.call_args_list,
            [
                # The test*.efi files match the glob,
                # the boot*.efi files don't.
                mock.call(self.efi_boot_dir / "testia32.efi"),
                mock.call(self.efi_boot_dir / "testx64.efi"),
                # Two syslinux kernels.
                mock.call(self.syslinux_dir / "vmlinuz.A"),
                mock.call(self.syslinux_dir / "vmlinuz.B"),
                # One kernel in the target dir.
                mock.call(self.target_dir / "vmlinuz-5.10.156"),
            ],
        )

        # Check that `inject_vbpubk` was called on both the crdyboot
        # executables.
        self.assertEqual(
            mock_inject_vbpubk.call_args_list,
            [
                mock.call(self.efi_boot_dir / "crdybootia32.efi", self.keys),
                mock.call(self.efi_boot_dir / "crdybootx64.efi", self.keys),
            ],
        )

        # Check that `create_detached_signature` was called on both
        # the crdyboot executables.
        self.assertEqual(
            mock_detached_sig.call_args_list,
            [
                mock.call(self.efi_boot_dir / "crdybootia32.efi"),
                mock.call(self.efi_boot_dir / "crdybootx64.efi"),
            ],
        )

    @mock.patch("sign_uefi.inject_vbpubk")
    @mock.patch.object(sign_uefi.Signer, "create_detached_signature")
    @mock.patch.object(sign_uefi.Signer, "sign_efi_file")
    def test_no_crdyshim_key(
        self, _mock_sign, _mock_detached_sig, _mock_inject_vbpubk
    ):
        """Test for older keysets that don't have the crdyshim key."""
        self.keys.crdyshim_private_key.unlink()

        # Error: crdyboot files are supposed to be signed, but the
        # crdyshim key isn't present.
        with self.assertRaises(SystemExit):
            sign_uefi.sign_target_dir(
                self.target_dir, self.keys, "crdyboot*.efi"
            )

        # Success: the crdyboot files aren't present, so the crdyshim
        # key is not required.
        (self.efi_boot_dir / "crdybootia32.efi").unlink()
        (self.efi_boot_dir / "crdybootx64.efi").unlink()
        sign_uefi.sign_target_dir(self.target_dir, self.keys, "crdyboot*.efi")

    @mock.patch.object(sign_uefi.Signer, "sign_efi_file")
    def test_sign_target_file(self, mock_sign):
        # Test signing a specific file.
        sign_uefi.sign_target_file(
            self.efi_boot_dir / "bootia32.efi", self.keys
        )

        # Check that we made the expected signer call.
        self.assertIn(
            [
                mock.call(self.efi_boot_dir / "bootia32.efi"),
            ],
            mock_sign.call_args_list,
        )

    @mock.patch("sign_uefi.subprocess.run")
    def test_inject_vbpubk(self, mock_run):
        efi_file = self.efi_boot_dir / "crdybootx64.efi"
        sign_uefi.inject_vbpubk(efi_file, self.keys)

        # Check that the expected command runs.
        self.assertEqual(
            mock_run.call_args_list,
            [
                mock.call(
                    [
                        "sudo",
                        "objcopy",
                        "--update-section",
                        f".vbpubk={self.keys.kernel_subkey_vbpubk}",
                        efi_file,
                    ],
                    check=True,
                )
            ],
        )

    @mock.patch("sign_uefi.subprocess.run")
    def test_create_detached_signature(self, mock_run):
        with tempfile.TemporaryDirectory() as tempdir:
            tempdir = Path(tempdir)
            signer = sign_uefi.Signer(tempdir, self.keys)

            efi_file = self.efi_boot_dir / "crdybootx64.efi"
            signer.create_detached_signature(efi_file)

            # Check that the expected commands run.
            self.assertEqual(
                mock_run.call_args_list,
                [
                    mock.call(
                        [
                            "openssl",
                            "pkeyutl",
                            "-sign",
                            "-rawin",
                            "-in",
                            efi_file,
                            "-inkey",
                            self.keys.crdyshim_private_key,
                            "-out",
                            tempdir / "crdybootx64.sig",
                        ],
                        check=True,
                    ),
                    mock.call(
                        [
                            "sudo",
                            "cp",
                            tempdir / "crdybootx64.sig",
                            self.efi_boot_dir / "crdybootx64.sig",
                        ],
                        check=True,
                    ),
                ],
            )


class TestUtils(unittest.TestCase):
    """Test utility functions in sign_uefi.py."""

    def test_is_pkcs11_key_path(self):
        self.assertFalse(sign_uefi.is_pkcs11_key_path(Path("private_key.rsa")))

        self.assertTrue(
            sign_uefi.is_pkcs11_key_path("pkcs11:object=private_key")
        )


if __name__ == "__main__":
    unittest.main()
