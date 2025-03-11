#!/bin/bash
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Load common constants and variables.
. "$(dirname "$0")/common.sh"

# Abort on error and uninitialized variables.
set -eu

declare -A -r REQUIRED_BIT_MASKS=(
  # Bit 58 - PSP_S0I3_RESUME_VERSTAGE - Run PSP verstage during S0i3 resume.
  # Checks that FW images have not been tampered with when exiting S0i3.
  [guybrush]="$((1 << 58))"
  [zork]="0x0"
)

declare -A -r FORBIDDEN_BIT_MASKS=(
  [guybrush]="0x0"
  [zork]="0x0"
)

# Grunt uses an old firmware format that amdfwread cannot read.
# See b/233787191 for skyrim.
BOARD_IGNORE_LIST=(grunt skyrim)

usage() {
  echo "$0: Validate AMD PSP soft-fuse flags contained in a ChromeOS image." \
    "These flags can have security implications and control debug features."
  echo "Usage $0 <image> <board>"
}

main() {
  if [[ $# -ne 2 ]]; then
    usage
    exit 1
  fi

  local image="$1"
  local board="$2"

  # Check the ignore list.
  if [[ " ${BOARD_IGNORE_LIST[*]} " == *" ${board} "* ]]; then
   echo "Skipping ignore-listed board ${board}"
   exit 0
  fi

  # Mount the image.
  local loopdev rootfs
  if [[ -d "${image}" ]]; then
    rootfs="${image}"
  else
    rootfs="$(make_temp_dir)"
    loopdev="$(loopback_partscan "${image}")"
    mount_loop_image_partition_ro "${loopdev}" 3 "${rootfs}"
  fi

  local firmware_bundle shellball_dir
  firmware_bundle="${rootfs}/usr/sbin/chromeos-firmwareupdate"
  shellball_dir="$(make_temp_dir)"

  # Extract our firmware.
  if ! extract_firmware_bundle "${firmware_bundle}" "${shellball_dir}"; then
    die "Failed to extract firmware bundle"
  fi

  # Find our images.
  declare -a images
  readarray -t images < <(find "${shellball_dir}" -iname 'bios-*')

  # Validate that all our AP FW images are AMD images.
  local image
  for image in "${images[@]}"; do
    # With no args, amdfwread will just attempt to validate the FW header.
    # On non-AMD FW this will fail, allowing us to skip non-AMD FW images.
    if ! amdfwread "${image}" &> /dev/null; then
      if [[ ! -v "REQUIRED_BIT_MASKS[${board}]" &&
            ! -v "FORBIDDEN_BIT_MASKS[${board}]" ]]; then
        # If we have an invalid FW image and don't have bitsets for this board
        # then this isn't an AMD board, exit successfully.
        exit 0
      else
        die "Found invalid AMD AP FW image"
      fi
    fi
  done

  # Get the board specific bit masks.
  local required_bit_mask forbidden_bit_mask

  if [[ ! -v "REQUIRED_BIT_MASKS[${board}]" ]]; then
    die "Missing PSP required bit mask set for ${board}"
  fi

  if [[ ! -v "FORBIDDEN_BIT_MASKS[${board}]" ]]; then
    die "Missing PSP forbidden bit mask set for ${board}"
  fi

  required_bit_mask="${REQUIRED_BIT_MASKS[${board}]}"
  forbidden_bit_mask="${FORBIDDEN_BIT_MASKS[${board}]}"

  # Check the soft-fuse bits
  for image in "${images[@]}"; do
    local soft_fuse soft_fuse_output forbidden_set missing_set
    if ! soft_fuse_output="$(amdfwread --soft-fuse "${image}")"; then
      die "'amdfwread --soft-fuse ${image}' failed"
    fi

    # Output format from amdfwread is Soft-fuse:value, where value is in hex.
    soft_fuse="$(echo "${soft_fuse_output}" | \
      sed -E -n 's/Soft-fuse:(0[xX][0-9a-fA-F]+)/\1/p')"
    if [[ -z "${soft_fuse}" ]]; then
      die "Could not parse Soft-fuse value from output: '${soft_fuse_output}'"
    fi

    forbidden_set="$((soft_fuse & forbidden_bit_mask))"
    if [[ "${forbidden_set}" != 0 ]]; then
      local forbidden_hex
      forbidden_hex="$(printf %#x "${forbidden_set}")"
      die "${image}: Forbidden AMD PSP soft-fuse bits set: ${forbidden_hex}"
    fi

    missing_set="$((~soft_fuse & required_bit_mask))"
    if [[ "${missing_set}" != 0 ]]; then
      local missing_hex
      missing_hex="$(printf %#x "${missing_set}")"
      die "${image}: Required AMD PSP soft-fuse bits not set: ${missing_hex}"
    fi
  done
}
main "$@"
