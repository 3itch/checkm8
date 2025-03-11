#!/bin/bash

# Copyright 2010 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Customizes a Chrome OS release image by setting /etc/lsb-release values.

# Load common constants and variables.
. "$(dirname "$0")/common.sh"

set_lsb_release_keyval() {
  local rootfs=$1
  local lsb="${rootfs}/etc/lsb-release"
  local key=$2
  local value=$3
  local data
  data=$(
    (
    grep -Ev "^${key}=" "${lsb}"
    echo "${key}=${value}"
    ) | sort
  )
  sudo tee "${lsb}" <<<"${data}" >/dev/null
}

main() {
  set -e

  if [[ $(( $# % 2 )) -eq 0 ]]; then
    cat <<EOF
Usage: $PROG <image.bin> [<key> <value> [<key> <value> ...]]

Examples:

$ $PROG chromiumos_image.bin

Dumps /etc/lsb-release from chromiumos_image.bin to stdout.

$ $PROG chromiumos_image.bin CHROMEOS_RELEASE_DESCRIPTION "New description"

Sets the CHROMEOS_RELEASE_DESCRIPTION key's value to "New description"
in /etc/lsb-release in chromiumos_image.bin, sorts the keys and dumps
the updated file to stdout.

EOF
    exit 1
  fi

  # If there are no key/value pairs to process, we don't need write access.
  local ro=$([[ $# -eq 0 ]] && echo true || echo false)

  local image=$1
  shift
  local loopdev rootfs

  if [[ -d "${image}" ]]; then
    rootfs="${image}"
  else
    rootfs=$(make_temp_dir)
    loopdev=$(loopback_partscan "${image}")

    if ${ro}; then
      mount_loop_image_partition_ro "${loopdev}" 3 "${rootfs}"
    else
      mount_loop_image_partition "${loopdev}" 3 "${rootfs}"
      touch "${image}"  # Updates the image modification time.
    fi
  fi

  # Process all the key/value pairs.
  local key value
  while [[ $# -ne 0 ]]; do
    key=$1 value=$2
    shift 2
    set_lsb_release_keyval "${rootfs}" "${key}" "${value}"
  done
  if ! ${ro}; then
    restore_lsb_selinux "${rootfs}/etc/lsb-release"
  fi

  # Dump the final state.
  cat "${rootfs}/etc/lsb-release"

  # Dump security context for lsb-release file
  getfattr --absolute-names -n security.selinux "${rootfs}/etc/lsb-release"
}

main "$@"
