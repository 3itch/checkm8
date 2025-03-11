#!/bin/bash -eu
#
# Copyright 2012 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This generates the pre-change test data used to ensure that
# modifications to vb2_fw_preamble and vb2_kernel_preamble will not
# break the signing tools for older releases. This was run *before*
# any modifications, so be sure to revert the repo back to the correct
# point if you need to run it again.


# Load common constants and variables for tests.
. "$(dirname "$0")/common.sh"

# Load routines to generate keypairs
. "${ROOT_DIR}/scripts/keygeneration/common.sh"

# all algs
algs="0 1 2 3 4 5 6 7 8 9 10 11"

# output directories
PREAMBLE_DIR="${SCRIPT_DIR}/preamble_tests"
DATADIR="${PREAMBLE_DIR}/data"
V2DIR="${PREAMBLE_DIR}/preamble_v2x"

for d in "${PREAMBLE_DIR}" "${DATADIR}" "${V2DIR}"; do
  [ -d "$d" ] || mkdir -p "$d"
done


# generate a bunch of data keys
for d in $algs; do
  make_pair "${DATADIR}/data_$d" "$d"
done

# generate a bunch of root keys
for r in $algs; do
  make_pair "${DATADIR}/root_$r" "$r"
done

# generate keyblocks using all possible combinations
for d in $algs; do
  for r in $algs; do
     make_keyblock "${DATADIR}/kb_${d}_${r}" 15 \
       "${DATADIR}/data_$d" "${DATADIR}/root_$r"
  done
done

# make a dummy kernel key because we have to have one (crosbug.com/27142)
make_pair "${DATADIR}/dummy_0" 0

# and a few more dummy files just because (crosbug.com/23548)
echo "hi there" > "${DATADIR}/dummy_config.txt"

# make some fake data
dd if=/dev/urandom of="${DATADIR}/FWDATA" bs=32768 count=1
dd if=/dev/urandom of="${DATADIR}/KERNDATA" bs=32768 count=1


# Now sign the firmware and kernel data in all the possible ways using the
# pre-change tools.
for d in $algs; do
  for r in $algs; do
    "${FUTILITY}" sign \
      --signprivate "${DATADIR}/data_${d}.vbprivk" \
      --keyblock "${DATADIR}/kb_${d}_${r}.keyblock" \
      --kernelkey "${DATADIR}/dummy_0.vbpubk" \
      --version 1 \
      --fv "${DATADIR}/FWDATA" \
      --outfile "${V2DIR}/fw_${d}_${r}.vblock"
    "${FUTILITY}" sign \
      --signprivate "${DATADIR}/data_${d}.vbprivk" \
      --keyblock "${DATADIR}/kb_${d}_${r}.keyblock" \
      --config "${DATADIR}/dummy_config.txt" \
      --arch arm \
      --version 1 \
      --vmlinuz "${DATADIR}/KERNDATA" \
      --outfile "${V2DIR}/kern_${d}_${r}.vblock"
  done
done
