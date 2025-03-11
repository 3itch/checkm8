#!/bin/bash

# Copyright 2012 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Verify that update payload verification is enabled.

# Abort on error.
set -e

# Load common constants and variables.
. "$(dirname "$0")/common.sh"

usage() {
  echo "Usage: $PROG image"
}

main() {
  if [ $# -ne 1 ]; then
    usage
    exit 1
  fi

  local image=$1

  local loopdev rootfs
  if [[ -d "${image}" ]]; then
    rootfs="${image}"
  else
    rootfs=$(make_temp_dir)
    loopdev=$(loopback_partscan "${image}")
    mount_loop_image_partition_ro "${loopdev}" 3 "${rootfs}"
  fi
  local key_location="/usr/share/update_engine/update-payload-key.pub.pem"
  if [ ! -e "$rootfs/$key_location" ]; then
    die "Update payload verification key not found at $key_location"
  fi
}

main "$@"
