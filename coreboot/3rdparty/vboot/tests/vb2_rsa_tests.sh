#!/bin/bash

# Copyright 2010 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Run tests for RSA Signature verification.

# Load common constants and variables.
. "$(dirname "$0")/common.sh"

set -e

return_code=0
TEST_FILE=${TESTCASE_DIR}/test_file

function test_signatures {
  algorithmcounter=0
  for keylen in "${key_lengths[@]}"
  do
    for hashalgo in "${hash_algos[@]}"
    do
      echo -e "For ${COL_YELLOW}RSA-$keylen and $hashalgo${COL_STOP}:"
      if ! "${BIN_DIR}/verify_data" "$algorithmcounter" \
        "${TESTKEY_DIR}/key_rsa${keylen}.keyb" \
        "${TEST_FILE}.rsa${keylen}_${hashalgo}.sig" \
        "${TEST_FILE}"
      then
        return_code=255
      fi
      algorithmcounter=$((algorithmcounter + 1))
    done
  done
  echo -e "Peforming ${COL_YELLOW}PKCS #1 v1.5 Padding Tests${COL_STOP}..."
  "${TEST_DIR}/vb20_rsa_padding_tests" \
    "${TESTKEY_DIR}/rsa_padding_test_pubkey.keyb"
  if [ -e "${TEST_DIR}/vb20_hwcrypto_rsa_padding_tests" ]
  then
    "${TEST_DIR}/vb20_hwcrypto_rsa_padding_tests" \
      "${TESTKEY_DIR}/rsa_padding_test_pubkey.keyb"
  fi
}

check_test_keys
echo "Testing signature verification..."
test_signatures

exit $return_code
