#!/bin/bash

# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# End-to-end test for vboot2 firmware verification

# Load common constants and variables.
. "$(dirname "$0")/common.sh"

set -e

echo 'Creating test firmware'

# Run tests in a dedicated directory for easy cleanup or debugging.
DIR="${TEST_DIR}/vb2fw_test_dir"
[ -d "$DIR" ] || mkdir -p "$DIR"
echo "Testing vb2_verify_fw in $DIR"
cd "$DIR"

# Dummy firmware body
echo 'This is a test firmware body.  This is only a test.  Lalalalala' \
    > body.test

algo_to_rsa()
{
  case $1 in
  0|1|2) printf "rsa1024";;
  3|4|5) printf "rsa2048";;
  6|7|8) printf "rsa4096";;
  9|10|11) printf "rsa8192";;
  *) exit 1;;
  esac
}

algo_to_sha()
{
  case $1 in
  0|3|6|9) printf "sha1";;
  1|4|7|10) printf "sha256";;
  2|5|8|11) printf "sha512";;
  *) exit 1;;
  esac
}

run_test()
{
  local root_algo=$1
  local fw_algo=$2
  local kern_algo=$3

  local root_rsa
  local fw_rsa
  local kern_rsa
  root_rsa="$(algo_to_rsa "${root_algo}")"
  fw_rsa="$(algo_to_rsa "${fw_algo}")"
  kern_rsa="$(algo_to_rsa "${kern_algo}")"

  local root_sha
  local fw_sha
  root_sha="$(algo_to_sha "${root_algo}")"
  fw_sha="$(algo_to_sha "${fw_algo}")"

  # Pack keys using original vboot utilities
  "${FUTILITY}" vbutil_key --pack rootkey.test \
      --key "${TESTKEY_DIR}/key_${root_rsa}.keyb" \
      --algorithm "${root_algo}"
  "${FUTILITY}" vbutil_key --pack fwsubkey.test \
      --key "${TESTKEY_DIR}/key_${fw_rsa}.keyb" \
      --algorithm "${fw_algo}"
  "${FUTILITY}" vbutil_key --pack kernkey.test \
      --key "${TESTKEY_DIR}/key_${kern_rsa}.keyb" \
      --algorithm "${kern_algo}"

  # Create a GBB with the root key
  "${FUTILITY}" gbb -c 128,2400,0,0 gbb.test
  "${FUTILITY}" gbb gbb.test -s --hwid='Test GBB' \
    --rootkey=rootkey.test

  # Keyblock with firmware subkey is signed by root key
  "${FUTILITY}" vbutil_keyblock --pack keyblock.test \
      --datapubkey fwsubkey.test \
      --signprivate "${TESTKEY_DIR}/key_${root_rsa}.${root_sha}.vbprivk"

  # Firmware preamble is signed with the firmware subkey
  "${FUTILITY}" sign \
    --version 1 \
    --signprivate "${TESTKEY_DIR}/key_${fw_rsa}.${fw_sha}.vbprivk" \
    --keyblock keyblock.test \
    --kernelkey kernkey.test \
    --fv body.test \
    --outfile vblock.test

  echo "Verifying test firmware using vb2_verify_fw" \
    "(root=${root_algo}, fw=${fw_algo}, kernel=${kern_algo})"

  # Verify the firmware using vboot2 checks
  "${TEST_DIR}/vb20_verify_fw" gbb.test vblock.test body.test
  if [ -e "${TEST_DIR}/vb20_hwcrypto_verify_fw" ]
  then
    echo "Verifying test firmware using vb20_hwcrypto_verify_fw" \
      "(root=${root_algo}, fw=${fw_algo}, kernel=${kern_algo})"
    "${TEST_DIR}/vb20_hwcrypto_verify_fw" gbb.test vblock.test body.test
  fi

  happy 'vb2_verify_fw succeeded'
}

run_test 11 7 4
run_test 11 11 11
run_test 1 1 1
