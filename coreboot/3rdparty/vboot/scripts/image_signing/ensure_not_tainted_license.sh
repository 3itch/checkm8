#!/bin/bash
#
# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This script ensures absence of a <!-- tainted --> tag in image's license.

# Abort on error.
set -e

# Load common constants and variables.
. "$(dirname "$0")/common.sh"

usage() {
  echo "Usage ${PROG} image"
}

main() {
  if [[ $# -ne 1 ]]; then
    usage
    exit 1
  fi

  local image="$1"

  local loopdev rootfs
  if [[ -d "${image}" ]]; then
    rootfs="${image}"
  else
    rootfs=$(make_temp_dir)
    loopdev=$(loopback_partscan "${image}")
    mount_loop_image_partition_ro "${loopdev}" 3 "${rootfs}"
  fi

  local license_dir license license_gz tainted_tag tainted_status
  license_dir="${rootfs}/opt/google/chrome/"
  if [[ ! -d "${license_dir}" ]]; then
    echo "Directory ${license_dir} does not exist. Skipping the tainted check."
    exit 0
  fi

  license=$(find "${license_dir}" -name about_os_credits.html 2>/dev/null)
  license_gz=$(find "${license_dir}" -name about_os_credits.html.gz 2>/dev/null)
  if [[ -n "${license_gz}" ]]; then
    local tmpfile
    tmpfile=$(make_temp_file)
    gunzip --stdout "${license_gz}" > "${tmpfile}"
    license="${tmpfile}"
  fi
  if [[ -z "${license}" ]]; then
    echo "License file about_os_credits.html not found in ${license_dir}."
    echo "Skipping the check of tainted license."
    exit 0
  fi

  tainted_tag="<!-- tainted -->"
  # Add "|| :" to the grep command to prevent it from returning error code 1 if
  # no match is found, which would cause the script to exit immediately with
  # error code 1 due to set -e.
  tainted_status=$(grep "${tainted_tag}" "${license}") || :
  if [[ -n "${tainted_status}" ]]; then
    echo "${license}:"
    echo "License file contains packages with LICENSE=TAINTED."
    echo "Remove those packages or modify their license to allow signing."
    # Print the list of tainted packages.
    sed -n '/Image is TAINTED/,/<\/ul>/{
      # Strip out HTML tags.
      s/<[^>]*>//g
      # Delete any empty lines.
      /^[[:space:]]*$/d
      p
    }' "${license}"
    exit 1
  fi
  exit 0
}
main "$@"
