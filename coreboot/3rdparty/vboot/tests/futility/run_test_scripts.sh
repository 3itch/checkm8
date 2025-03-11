#!/bin/bash -eu
# Copyright 2013 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Load common constants and variables.
. "$(dirname "$0")/../common.sh"

OUTDIR="${BUILD_RUN}/tests/futility_test_results"
[ -d "$OUTDIR" ] || mkdir -p "$OUTDIR"

# Let each test know where to find things...
export BUILD_RUN
export SRCDIR
export FUTILITY
export SCRIPT_DIR
export OUTDIR

# These are the scripts to run. Binaries are invoked directly by the Makefile.
TESTS="
${SCRIPT_DIR}/futility/test_create.sh
${SCRIPT_DIR}/futility/test_dump_fmap.sh
${SCRIPT_DIR}/futility/test_flash_util.sh
${SCRIPT_DIR}/futility/test_gbb_utility.sh
${SCRIPT_DIR}/futility/test_load_fmap.sh
${SCRIPT_DIR}/futility/test_main.sh
${SCRIPT_DIR}/futility/test_rwsig.sh
${SCRIPT_DIR}/futility/test_show_and_verify.sh
${SCRIPT_DIR}/futility/test_show_usbpd1.sh
${SCRIPT_DIR}/futility/test_sign_firmware.sh
${SCRIPT_DIR}/futility/test_sign_fw_main.sh
${SCRIPT_DIR}/futility/test_sign_kernel.sh
${SCRIPT_DIR}/futility/test_sign_keyblocks.sh
${SCRIPT_DIR}/futility/test_sign_usbpd1.sh
${SCRIPT_DIR}/futility/test_update.sh
${SCRIPT_DIR}/futility/test_file_types.sh
${SCRIPT_DIR}/futility/test_gscvd.sh
${SCRIPT_DIR}/futility/test_read.sh
${SCRIPT_DIR}/futility/test_vbutil_output.sh
"

# Get ready...
pass=0
progs=0

##############################################################################
# Invoke the scripts that test the builtin functions.

# Let the test scripts use >&3 to indicate progress
exec 3>&1

echo "-- builtin --"
for i in $TESTS; do
  j=${i##*/}

  : $(( progs++ ))

  echo -n "$j ... "
  rm -rf "${OUTDIR}/$j."*
  rc=$("$i" "$FUTILITY" 1>"${OUTDIR}/$j.stdout" \
    2>"${OUTDIR}/$j.stderr" || echo "$?")
  echo "${rc:-0}" > "${OUTDIR}/$j.return"
  if [ ! "$rc" ]; then
    echo -e "${COL_GREEN}PASSED${COL_STOP}"
    : $(( pass++ ))
    rm -f "${OUTDIR}/$j".{stdout,stderr,return}
  else
    echo -e "${COL_RED}FAILED (${rc:-0}). Stdout is recorded in" \
      "${OUTDIR}/$j.stdout${COL_STOP}"
    cat "${OUTDIR}/$j.stderr"
  fi
done

##############################################################################
# How'd we do?

if [ "$pass" -eq "$progs" ]; then
  echo -e "${COL_GREEN}Success: $pass / $progs passed${COL_STOP}"
  exit 0
fi

echo -e "${COL_RED}FAIL: $pass / $progs passed${COL_STOP}"
exit 1
