#!/bin/bash -eux
# Copyright 2013 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

me=${0##*/}
TMP="${me}.tmp"

# Work in scratch directory
cd "${OUTDIR}"

# Good FMAP
"${FUTILITY}" dump_fmap -F "${SCRIPT_DIR}/futility/data_fmap.bin"  > "${TMP}"
cmp "${SCRIPT_DIR}/futility/data_fmap_expect_f.txt" "${TMP}"

"${FUTILITY}" dump_fmap -p "${SCRIPT_DIR}/futility/data_fmap.bin"  > "${TMP}"
cmp "${SCRIPT_DIR}/futility/data_fmap_expect_p.txt" "${TMP}"

"${FUTILITY}" dump_fmap -h "${SCRIPT_DIR}/futility/data_fmap.bin"  > "${TMP}"
cmp "${SCRIPT_DIR}/futility/data_fmap_expect_h.txt" "${TMP}"

"${FUTILITY}" dump_fmap -e "${SCRIPT_DIR}/futility/data_fmap3.bin"  > "${TMP}"
cmp "${SCRIPT_DIR}/futility/data_fmap_expect_e.txt" "${TMP}"


# This should fail because the input file is truncated and doesn't really
# contain the stuff that the FMAP claims it does.
if "${FUTILITY}" dump_fmap -x "${SCRIPT_DIR}/futility/data_fmap.bin" FMAP; \
  then false; fi

# This should fail because of invalid section name.
if "${FUTILITY}" dump_fmap -x "${SCRIPT_DIR}/futility/data_fmap.bin" NO_SUCH; \
  then false; fi

# However, this should work.
"${FUTILITY}" dump_fmap -x "${SCRIPT_DIR}/futility/data_fmap.bin" SI_DESC > \
  "${TMP}"
cmp "${SCRIPT_DIR}/futility/data_fmap_expect_x.txt" "${TMP}"

# Redirect dumping to a different place
"${FUTILITY}" dump_fmap -x "${SCRIPT_DIR}/futility/data_fmap.bin" SI_DESC:FOO \
  > "${TMP}"
cmp "${SCRIPT_DIR}/futility/data_fmap_expect_x2.txt" "${TMP}"
cmp SI_DESC FOO

# This FMAP has problems, and should fail.
if "${FUTILITY}" dump_fmap -h "${SCRIPT_DIR}/futility/data_fmap2.bin" > \
  "${TMP}"; then false; fi
cmp "${SCRIPT_DIR}/futility/data_fmap2_expect_h.txt" "${TMP}"

"${FUTILITY}" dump_fmap -hh "${SCRIPT_DIR}/futility/data_fmap2.bin" > "${TMP}"
cmp "${SCRIPT_DIR}/futility/data_fmap2_expect_hh.txt" "${TMP}"

"${FUTILITY}" dump_fmap -hhH "${SCRIPT_DIR}/futility/data_fmap2.bin" > "${TMP}"
cmp "${SCRIPT_DIR}/futility/data_fmap2_expect_hhH.txt" "${TMP}"


# cleanup
rm -f "${TMP}"* FMAP SI_DESC FOO
exit 0
