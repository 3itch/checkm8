#!/bin/bash -eux
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

if [[ -z ${SCRIPT_DIR+x} ]]; then
  # must be running standalone
  SCRIPT_DIR="$(readlink -f "$(dirname "$0")"/..)"
  FUTILITY="${SCRIPT_DIR}/../build/futility/futility"
fi

if [[ ! -e ${FUTILITY} ]]; then
  echo "The futility app not available, run 'make futil' in the top directory" \
       >&2
  exit 1
fi

KEYS_DIR="$(readlink -f "${SCRIPT_DIR}/devkeys")"
TMPD="$(mktemp -d /tmp/"$(basename "$0")".XXXXX)"
trap '/bin/rm -rf "${TMPD}"' EXIT

# Test FMAP sections were taken from Nivviks image, which is 32M in size.
FW_IMAGE_SIZE_K=$(( 32 * 1024 ))

# FMAP offset in the original image
FMAP_OFFSET_K=28696

main() {
  local bios_blob
  local command_args
  local warn
  local fmap_blob
  local hwid
  local pubkhash
  local section
  local stderr_output

  cd "${SCRIPT_DIR}/futility"

  # Create a blob of the firmware image size.
  bios_blob="${TMPD}/image.bin"
  cat /dev/zero | tr '\000' '\377' | \
    dd of="${bios_blob}" bs=1K count="${FW_IMAGE_SIZE_K}" status=none

  # Paste the FMAP blob at the known location
  fmap_blob="data/nivviks.FMAP"
  dd if="${fmap_blob}" of="${bios_blob}" bs=1K seek="${FMAP_OFFSET_K}" \
     conv=notrunc status=none

  # Paste other available FMAP areas into the image.
  command_args=()
  for section in data/nivviks.[A-Z]*; do
    local name

    if [[ ${section} =~ .*FMAP ]]; then
      continue
    fi

    name="${section##*.}"
    command_args+=( "${name}:${section}" )
  done
  "${FUTILITY}" load_fmap "${bios_blob}" "${command_args[@]}"

  # Make sure gbb flags are nonzero
  "${FUTILITY}" gbb --set --flags=1 "${bios_blob}"

  # Sign the blob using ranges already present in the RO_GSCVD section.
  "${FUTILITY}" gscvd --keyblock "${KEYS_DIR}"/arv_platform.keyblock \
                --platform_priv "${KEYS_DIR}"/arv_platform.vbprivk \
                --board_id XYZ1 \
                --root_pub_key "${KEYS_DIR}"/arv_root.vbpubk "${bios_blob}"

  # Calculate root pub key hash
  pubkhash="$( "${FUTILITY}" gscvd --root_pub_key \
      "${KEYS_DIR}"/arv_root.vbpubk | tail -1)"

  # Message printed on stderr in case signature matches only after zeroing GBB
  # flags.
  warn="WARNING: validate_gscvd: Ranges digest matches with zeroed GBB flags"

  # Run verification, this one is expected to succeed but report GBB flags
  # mismatch.
  stderr_output=$("${FUTILITY}" gscvd "${bios_blob}" "${pubkhash}" 2>&1)
  if [[ $? != 0 ]] ; then
    echo "Unexpected failure with nonzero GBB!" >&2
    exit 1
  fi
  if [[ ${stderr_output} !=  "${warn}" ]]; then
    echo "Unexpected error message \"${stderr_output}\" with nonzero GBB!"
    exit 1
  fi

  # Clear the flags and try verifying again, should succeed this time.
  "${FUTILITY}" gbb --set --flags=0 "${bios_blob}"
  if ! "${FUTILITY}" gscvd "${bios_blob}" "${pubkhash}" 2>/dev/null ; then
    echo "Unexpected signature MISmatch!" >&2
    exit 1
  fi

  # Change HWID and see that signature still matches.
  hwid="$("${FUTILITY}" gbb --hwid "${bios_blob}" | sed 's/.*: //')"
  "${FUTILITY}" gbb  --set --hwid="${hwid}xx" "${bios_blob}"
  if ! "${FUTILITY}" gscvd "${bios_blob}" "${pubkhash}" 2>/dev/null ; then
    echo "Unexpected signature MISmatch after modifying HWID!" >&2
    exit 1
  fi

  # Modify the recovery key and see that signature verification fails.
  "${FUTILITY}" gbb --set \
                --recoverykey="${KEYS_DIR}"/recovery_kernel_data_key.vbpubk \
                 "${bios_blob}"
  if "${FUTILITY}" gscvd "${bios_blob}" "${pubkhash}" 2>/dev/null ; then
    echo "Unexpected signature match after updating recovery key!" >&2
    exit 1
  fi
}

main "$@"
