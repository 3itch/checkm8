#!/bin/bash
# Copyright 2011 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Wrapper script for re-signing a firmware image.

# Determine script directory.
SCRIPT_DIR=$(dirname "$0")

# Load common constants and variables.
. "${SCRIPT_DIR}/common_minimal.sh"
. "${SCRIPT_DIR}/lib/keycfg.sh"

# Abort on error.
set -e

usage() {
  cat<<EOF
Usage: $0 <input_firmware> <key_dir> <output_firmware> [firmware_version] \
[loem_output_dir]

Signs <input_firmware> with keys in <key_dir>, setting firmware version
to <firmware_version>. Outputs signed firmware to <output_firmware>.
The <input_firmware> and <output_firmware> paths may be the same.
If no firmware version is specified, it is set as 1.
EOF
  exit 1
}

gbb_update() {
  local in_firmware="$1"
  local key_dir="$2"
  local out_firmware="$3"
  local rootkey="$4"

  # Replace the root and recovery key in the Google Binary Block of the
  # firmware.  Note: This needs to happen after calling resign_firmwarefd.sh
  # since it needs to be able to verify the firmware using the root key to
  # determine the preamble flags.
  futility gbb \
    -s \
    --recoverykey="${KEYCFG_RECOVERY_KEY_VBPUBK}" \
    --rootkey="${rootkey}" \
    "${in_firmware}" \
    "${out_firmware}"
}

# Sign a single firmware image.
# ARGS: [key_dir] [loem_index] [loemid]
sign_one() {
  local key_dir="$1"
  local loem_index="$2"
  local loemid="$3"

  # Resign the firmware with new keys.
  "${SCRIPT_DIR}/resign_firmwarefd.sh" \
    "${in_firmware}" \
    "${temp_fw}" \
    "$(get_firmware_vbprivk "${loem_index}")" \
    "$(get_firmware_keyblock "${loem_index}")" \
    "${KEYCFG_KERNEL_SUBKEY_VBPUBK}" \
    "${firmware_version}" \
    "" \
    "${loem_output_dir}" \
    "${loemid}"
}

# Process all the keysets in the loem.ini file.
# ARGS: [key_dir]
sign_loems() {
  local key_dir="$1"
  local line loem_section=false loem_index loemid
  local rootkey

  while read line; do
    # Find the [loem] section.
    if ! ${loem_section}; then
      if grep -q "^ *\[loem\] *$" <<<"${line}"; then
        loem_section=true
      fi
      continue
    # Abort when we hit the next section.
    elif [[ ${line} == *"["* ]]; then
      break
    fi

    # Strip comments/whitespace.
    line=$(sed -e 's:#.*::' -e 's:^ *::' -e 's: *$::' <<<"${line}")
    if [[ -z "${line}" ]]; then
      # Skip blank lines.
      continue
    fi

    loem_index=$(cut -d= -f1 <<<"${line}" | sed 's: *$::')
    loemid=$(cut -d= -f2 <<<"${line}" | sed 's:^ *::')

    echo "### Processing LOEM ${loem_index} ${loemid}"
    sign_one "${key_dir}" "${loem_index}" "${loemid}"

    rootkey="$(get_root_key_vbpubk "${key_index}")"
    cp "${rootkey}" "${loem_output_dir}/rootkey.${loemid}"

    if [[ ${loem_index} == "1" ]]; then
      gbb_update "${temp_fw}" "${key_dir}" "${out_firmware}" "${rootkey}"
    fi
    echo
  done <"${key_dir}/loem.ini"
}

main() {
  if [[ $# -lt 3 || $# -gt 5 ]]; then
    usage
  fi

  local in_firmware=$1
  local key_dir=$2
  local out_firmware=$3
  local firmware_version=${4:-1}
  local loem_output_dir=${5:-}

  local temp_fw=$(make_temp_file)

  setup_keycfg "${key_dir}"
  if [[ -e ${key_dir}/loem.ini ]]; then
    if [[ -z ${loem_output_dir} ]]; then
      die "need loem_output_dir w/loem keysets"
    fi
    sign_loems "${key_dir}"
  else
    sign_one "${key_dir}"
    gbb_update "${temp_fw}" "${key_dir}" "${out_firmware}" \
      "$(get_root_key_vbpubk)"
  fi
}
main "$@"
