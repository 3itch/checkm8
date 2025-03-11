#!/bin/bash
# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Abort on error.
set -e -o pipefail

# Determine script directory.
SCRIPT_DIR=$(dirname "$0")

# Load common constants and variables.
. "${SCRIPT_DIR}/common.sh"

usage() {
  cat <<EOF
Usage: ${PROG} <input_firmware> <key_dir> <output_firmware>

Signs <input_firmware> with keys in <key_dir>. Outputs signed firmware to
<output_firmware>.  The <input_firmware> and <output_firmware> paths should not
be the same.

For detail, reference the AMD documentation titled "OEM PSP VERSTAGE
BL FW Signing Key Pair Generation and Certificate Request Process"
http://dr/corp/drive/folders/1ySJyDgbH73W1lqrhxMvM9UYl5TtJt_mw

EOF

  if [[ $# -ne 0 ]]; then
    echo "$*" >&2
    exit 1
  else
    exit 0
  fi
}

# Check the arguments to make sure we have the correct number.
if [[ $# -lt 3 ]]; then
  usage "Error: Too few arguments"
fi
if [[ $# -gt 3 ]]; then
  usage "Error: Too many arguments"
fi

read_byte() {
  local position="$1"
  local file="$2"

  dd if="${file}" bs=1 count=1 skip="$((16#${position}))" status=none |
    hexdump -e '/1 "%X"'
}

write_byte() {
  local position="$1"
  local value="$2"
  local file="$3"

  printf "\x${value}" |
    dd of="${file}" bs=1 count=1 seek="${position}" conv=notrunc status=none
}

read_dword_le() {
  local position
  position=$(printf -- "%d" "$1")
  local file="$2"
  read_byte "${position}" "${file}"
  read_byte $((position + 1)) "${file}"
  read_byte $((position + 2)) "${file}"
  read_byte $((position + 3))
}

write_dword_le() {
  local position
  position=$(printf -- "%d" "$1")
  local value
  value=$(printf -- "%08x" "$2")
  local file="$3"

  write_byte "${position}" "${value:6:2}" "$file"
  write_byte $((position + 1)) "${value:4:2}" "$file"
  write_byte $((position + 2)) "${value:2:2}" "$file"
  write_byte $((position + 3)) "${value:0:2}" "$file"
}

filesize() {
  local file="$1"
  stat -c %s -- "${file}"
}

copy_key_id() {
  local input_file="$1"
  local input_offset
  input_offset=$(printf -- "%d" "$2")
  local output_file="$3"
  local output_offset
  output_offset=$(printf -- "%d" "$4")

  local id_size=16

  dd if="${input_file}" skip="${input_offset}" \
    of="${output_file}" seek="${output_offset}" \
    bs=1 count="${id_size}" conv=notrunc status=none
}

KEYNAME=psp_verstagebl_fw_signing

main() {
  local input_firmware="$1"
  local key_dir="$2"
  local output_firmware="$3"

  if [[ "${input_firmware}" == "${output_firmware}" ]]; then
    usage "Error: input and output files must not be the same"
  fi

  local amd_key="${key_dir}/${KEYNAME}.stkn"
  local hashtype
  local sig_size
  local temp_sig
  local temp_fw
  local fw_size
  local image_size

  temp_sig=$(make_temp_file)
  temp_fw=$(make_temp_file)

  # TODO: Differentiate sizes for Picasso vs later chips
  hashtype="-sha256"
  sig_size=256

  fw_size="$(($(filesize "${input_firmware}")))"
  fw_minus_header_size="$((fw_size - 256))"
  image_size="$((fw_size + sig_size))"

  cp "${input_firmware}" "${temp_fw}"

  # Refer to Appendix D in the AMD BIOS Signing Key Pair and Certification
  # Process document for what needs to be changed in the psp_verstage header.
  write_dword_le "0x14" "${fw_minus_header_size}" "${temp_fw}"
  write_dword_le "0x30" "1" "${temp_fw}"
  write_dword_le "0x6c" "${image_size}" "${temp_fw}"

  # TODO: Need the PSP verstage signing token from AMD to verify.
  copy_key_id "${amd_key}" "0x04" "${temp_fw}" "0x38"

  local cmd=(
    openssl dgst
    "${hashtype}"
    -sign "${key_dir}/${KEYNAME}.pem"
    -sigopt rsa_padding_mode:pss
    -sigopt rsa_pss_saltlen:-1
    -out "${temp_sig}"
  )

  "${cmd[@]}" "${temp_fw}"

  cat "${temp_fw}" "${temp_sig}" >"${output_firmware}"

  echo "Complete"
}

main "$@"
