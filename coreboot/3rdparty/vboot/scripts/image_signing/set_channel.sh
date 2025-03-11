#!/bin/bash

# Copyright 2012 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Changes the channel on a Chrome OS image.

# Load common constants and variables.
. "$(dirname "$0")/common.sh"

set -e

if [ $# -ne 2 ]; then
  cat <<EOF
Usage: $PROG <image.bin> <channel>

<image.bin>: Path to image.
<channel>: The new channel of the image.
EOF
  exit 1
fi

main() {
  local image=$1
  local to=$2
  local loopdev rootfs lsb

  if [[ -d "${image}" ]]; then
    rootfs="${image}"
  else
    rootfs=$(make_temp_dir)
    loopdev=$(loopback_partscan "${image}")
    mount_loop_image_partition "${loopdev}" 3 "${rootfs}"
  fi
  lsb="${rootfs}/etc/lsb-release"
  # Get the current channel on the image.
  local from=$(lsbval "${lsb}" 'CHROMEOS_RELEASE_TRACK')
  from=${from%"-channel"}
  echo "Current channel is '${from}'. Changing to '${to}'."

  local sudo
  if [[ ! -w ${lsb} ]] ; then
    sudo="sudo"
  fi
  ${sudo} sed -i "s/\b${from}\b/${to}/" "${lsb}" &&
    restore_lsb_selinux "${lsb}" &&
    echo "Channel change successful."
  cat "${lsb}"
}

main "$@"
