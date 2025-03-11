#!/bin/bash -eux
# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
# Tests for 'futility show' and 'futility verify'.

set -o pipefail

ME="${0##*/}"
TMP="${ME}.tmp"

# Set to 1 to update the expected output
UPDATE_MODE=0

# Test case: <name> <file> <error_level> <extra_options>
#   name: Test case name used to form the expected output file.
#     For example, if name is "abc", then the expected output file will be
#     "tests/futility/expect_output/show.abc".
#   file: Input file.
#   error_level:
#     0: Both 'futility show' and 'futility verify' expected to succeed.
#     1: 'show' expected to succeed, but 'verify' expected to fail.
#     2: Both 'show' and 'verify' expected to fail.
#   extra_options (optional): Extra options passed to 'show' or 'verify'.
TEST_CASES=(
  ## [type] pubkey/prikey
  "root_key.vbpubk tests/devkeys/root_key.vbpubk 0"
  "root_key.vbprivk tests/devkeys/root_key.vbprivk 0"
  "parseable.root_key.vbpubk tests/devkeys/root_key.vbpubk 0 -P"
  "parseable.root_key.vbprivk tests/devkeys/root_key.vbprivk 0 -P"
  ## [type] pubkey21/prikey21 (-P not supported)
  "sample.vbpubk2 tests/futility/data/sample.vbpubk2 0"
  "sample.vbprik2 tests/futility/data/sample.vbprik2 0"
  ## [type] pem (-P not supported)
  "key_rsa2048.pem tests/testkeys/key_rsa2048.pem 0"
  "key_rsa8192.pub.pem tests/testkeys/key_rsa8192.pub.pem 0"
  ## [type] keyblock
  "fw.keyblock tests/devkeys/firmware.keyblock 1"
  "parseable.fw.keyblock tests/devkeys/firmware.keyblock 1 -P"
  "fw.keyblock-pubkey tests/devkeys/firmware.keyblock 0 \
    --publickey tests/devkeys/root_key.vbpubk"
  "kernel.keyblock tests/devkeys/kernel.keyblock 1"
  "parseable.kernel.keyblock tests/devkeys/kernel.keyblock 1 -P"
  ## [type] fw_pre
  "fw_vblock tests/futility/data/fw_vblock.bin 1"
  "parseable.fw_vblock tests/futility/data/fw_vblock.bin 1 -P"
  "fw_vblock-pubkey tests/futility/data/fw_vblock.bin 1 \
    -k tests/futility/data/peppy_mp_root_key.vbpubk"
  "fw_vblock-pubkey-with-fv tests/futility/data/fw_vblock.bin 0 \
    -k tests/futility/data/peppy_mp_root_key.vbpubk \
    --fv tests/futility/data/fw_main_peppy.bin"
  "parseable.fw_vblock-pubkey-with-fv tests/futility/data/fw_vblock.bin 0 \
    -k tests/futility/data/peppy_mp_root_key.vbpubk \
    --fv tests/futility/data/fw_main_peppy.bin -P"
  "fw_vblock-pubkey-wrong tests/futility/data/fw_vblock.bin 1 \
    -k tests/devkeys/root_key.vbpubk \
    --fv tests/futility/data/fw_main_peppy.bin"
  "parseable.fw_vblock-pubkey-wrong tests/futility/data/fw_vblock.bin 1 \
    -k tests/devkeys/root_key.vbpubk \
    --fv tests/futility/data/fw_main_peppy.bin -P"
  # invalid data key algorithm
  # NOTE: '--type fw_pre' is necessary; otherwise the file will be recognized
  # as a keyblock file and 'futility show' will succeed.
  "fw_vblock_invalid_data_key \
    tests/futility/data/fw_vblock_invalid_data_key.bin 2 --type fw_pre"
  "parseable.fw_vblock_invalid_data_key \
    tests/futility/data/fw_vblock_invalid_data_key.bin 2 --type fw_pre -P"
  ## [type] gbb
  "gbb tests/futility/data/fw_gbb.bin 0"
  "parseable.gbb tests/futility/data/fw_gbb.bin 0 -P"
  ## [type] bios
  # valid bios with non-CBFS FW_MAIN_* sections
  "bios_peppy tests/futility/data/bios_peppy_mp.bin 0"
  "parseable.bios_peppy tests/futility/data/bios_peppy_mp.bin 0 -P"
  # valid bios without VBOOT_CBFS_INTEGRATION
  "bios_brya tests/futility/data/bios_brya_mp.bin 0"
  "parseable.bios_brya tests/futility/data/bios_brya_mp.bin 0 -P"
  # bios without VBOOT_CBFS_INTEGRATION; invalid keyblock in VBLOCK_B
  "bios_brya_invalid_keyblock \
    tests/futility/data/bios_brya_mp_invalid_vblock_b.bin 1"
  "parseable.bios_brya_invalid_keyblock \
    tests/futility/data/bios_brya_mp_invalid_vblock_b.bin 1 -P"
  # bios with VBOOT_CBFS_INTEGRATION; invalid metadata hash in VBLOCK_B
  "bios_coachz_cbfs tests/futility/data/bios_coachz_cbfs.bin 1"
  "parseable.bios_coachz_cbfs tests/futility/data/bios_coachz_cbfs.bin 1 -P"
  # valid bios with VBOOT_CBFS_INTEGRATION
  "bios_geralt_cbfs tests/futility/data/bios_geralt_cbfs.bin 0"
  "bios_geralt_cbfs tests/futility/data/bios_geralt_cbfs.bin 0 --type bios"
  "parseable.bios_geralt_cbfs tests/futility/data/bios_geralt_cbfs.bin 0 \
    --type bios -P"
  ## [type] kernel
  # kernel partition
  "kernel tests/futility/data/kernel_part.bin 1"
  "parseable.kernel tests/futility/data/kernel_part.bin 1 -P"
  "kernel-pubkey tests/futility/data/kernel_part.bin 0 \
    -k tests/futility/data/fw_dev_vblock.bin"
  "kernel-pubkey tests/futility/data/kernel_part.bin 0 \
    --type kernel -k tests/futility/data/fw_dev_vblock.bin"
  "kernel-pubkey-wrong tests/futility/data/kernel_part.bin 1 \
    --type kernel -k tests/futility/data/fw_vblock.bin"
  "rec_kernel tests/futility/data/rec_kernel_part.bin 1"
  "rec_kernel-pubkey tests/futility/data/rec_kernel_part.bin 0 \
    -k tests/devkeys/recovery_key.vbpubk"
  "parseable.rec_kernel-pubkey tests/futility/data/rec_kernel_part.bin 0 \
    -k tests/devkeys/recovery_key.vbpubk -P"
  "rec_kernel-pubkey-wrong tests/futility/data/rec_kernel_part.bin 1 \
    -k tests/devkeys/kernel_subkey.vbpubk"
  # kernel vblock
  "kernel_vblock tests/futility/data/kernel_vblock.bin 1"
  "parseable.kernel_vblock tests/futility/data/kernel_vblock.bin 1 -P"
)

check_diff()
{
  local gotfile="$1"
  local wantfile="$2"
  [[ "${UPDATE_MODE}" -gt 0 ]] && cp "${gotfile}" "${wantfile}"
  diff "${gotfile}" "${wantfile}"
}

for test_case in "${TEST_CASES[@]}"; do
  read -ra arr <<<"${test_case}"
  name="${arr[0]}"
  file="${arr[1]}"
  level="${arr[2]}"
  opts=()
  if [ "${#arr[@]}" -gt 3 ]; then
    opts=("${arr[@]:3}")
  fi

  outfile="show.${name}"
  succ_gotfile="${OUTDIR}/${outfile}"
  fail_gotfile="${OUTDIR}/${outfile}-fail"
  wantfile="${SRCDIR}/tests/futility/expect_output/${outfile}"

  succ_cmd=""
  fail_cmd=""
  if [ "${level}" -eq 0 ]; then
    succ_cmd="verify"
  elif [ "${level}" -eq 1 ]; then
    succ_cmd="show"
    fail_cmd="verify"
  else
    fail_cmd="show"
  fi

  if [ -n "${succ_cmd}" ]; then
    ( cd "${SRCDIR}" && "${FUTILITY}" "${succ_cmd}" "${file}" "${opts[@]}" ) \
      | tee "${succ_gotfile}"
    check_diff "${succ_gotfile}" "${wantfile}"
  fi

  if [ -n "${fail_cmd}" ]; then
    ( cd "${SRCDIR}" && ! "${FUTILITY}" "${fail_cmd}" "${file}" "${opts[@]}" ) \
      | tee "${fail_gotfile}" \
      || ( echo "Command expected to fail, but succeeded" && false )

    # The output of 'show' and 'verify' should be the same.
    check_diff "${fail_gotfile}" "${wantfile}"
  fi
done

# cleanup
rm -rf "${TMP}"*
exit 0
