#!/bin/bash
# Copyright 2024 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Load common constants and variables.
. "$(dirname "$0")/common.sh"

TMPD="$(mktemp -d /tmp/"$(basename "$0")".XXXXX)"
trap '/bin/rm -rf "${TMPD}"' EXIT

return_code=0

main() {
  local hostlib_def_symbols=$1
  local hostlib_undef_symbols=$2
  local never_def_vb2_functions="${TMPD}/vb2_undef.txt"

  if [ ! -s "${hostlib_def_symbols}" ] || [ ! -s "${hostlib_undef_symbols}" ]; then
    echo "Missing input data." >&2
    exit 1
  fi

  # We should see any vb2 symbols undefined.
  grep -vf "${hostlib_def_symbols}" "${hostlib_undef_symbols}" | \
    grep vb2 > "${never_def_vb2_functions}"

  if [ -s "${never_def_vb2_functions}" ]; then
    echo "libvboot_host: Unexpected undefined symbols: " >&2
    cat "${never_def_vb2_functions}" >&2
    return_code=1
  fi
  return "${return_code}"
}

main "$@"
