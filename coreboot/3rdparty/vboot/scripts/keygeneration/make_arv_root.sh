#!/bin/bash
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Create AP RO verification Root key pair for PreMp signing.

# Load common constants and functions.
# shellcheck source=common.sh
. "$(dirname "$0")/common.sh"

usage() {
  cat <<EOF
Usage: $0 [destination directory]

Output: arv_root.vbprivk and arv_root.vbpubk created in [destination dirctory]
        which by default is "./${ARV_ROOT_DIR}"
EOF
  exit 1
}

main() {
  local key_dir

  case $# in
    (0) # Use default directory.
      key_dir="${ARV_ROOT_DIR}"
      ;;
    (1)
      key_dir="$1"
      ;;
    (*)
      usage
  esac

  if [[ -d ${key_dir} ]]; then
    die "Destination directory \"${key_dir}\" exists. There can be only one!"
  fi

  mkdir -p "${key_dir}" || die "Failed to create \"${key_dir}\"."

  cd "${key_dir}" || die "Failed to cd to \"${key_dir}\"."

  make_pair "${ARV_ROOT_NAME_BASE}" "${ARV_ROOT_ALGOID}"
}

main "$@"
