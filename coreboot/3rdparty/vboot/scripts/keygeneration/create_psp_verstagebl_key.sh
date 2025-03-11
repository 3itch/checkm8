#!/bin/bash
# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Load common constants and functions.
# shellcheck source=common.sh
. "$(dirname "$0")/common.sh"

usage() {
  cat <<EOF
Usage: ${PROG} <PROJECT/DEVICE NAME> <OUTPUT DIRECTORY> <KEY SIZE>

Generate a key pair for signing the PSP_Verstage binary to be loaded by
the PSP bootloader.  For detail, reference the AMD documentation titled
"OEM PSP VERSTAGE BL FW Signing Key Pair Generation and Certificate Request
Process" - http://dr/corp/drive/folders/1ySJyDgbH73W1lqrhxMvM9UYl5TtJt_mw

Arguments:
- Output Directory: Location for the keys to be generated.  Must exist.
- Key size: 2048 for Picasso, Dali, & Pollock, 4096 for other F17h SOCs
EOF

  if [[ $# -ne 0 ]]; then
    echo "$*" >&2
    exit 1
  else
    exit 0
  fi
}

KEYNAME=psp_verstagebl_fw_signing

# Generate the key pair.
# ARGS: <name> <key> <keysize>
create_psp_key() {
  local name=$1
  local key=$2
  local keysize=$3

  [[ $# -eq 3 ]] || error "${FUNCNAME} requires 3 args"

  local plainname="psp_verstagebl_${name}_${keysize}"
  local embedname="psp_verstagebl_${name}"

  # HSM signer stuff -- need a unique name for the key.
  echo "Will use plain name: ${plainname}, and embed name: ${embedname}."

  local cmd=(
    openssl genrsa -F4 -out "${key}" "${keysize}"
  )
  echo "> ${cmd[@]}"
  "${cmd[@]}" || die "generating key failed"
}

# Generate the CSR for this key.
# ARGS: <output dir> key> <keysize>
create_psp_csr() {
  local dir=$1
  local key=$2
  local keysize=$3

  [[ $# -eq 3 ]] || error "${FUNCNAME} requires 3 args"

  local hash
  if [[ ${keysize} -eq 2048 ]]; then
    hash="sha256"
  else
    hash="sha384"
  fi

  local config="${dir}/${KEYNAME}.cnf"
  local csr="${dir}/${KEYNAME}.csr"

  cat <<EOF >"${config}"
[req]
default_md         = ${hash}
prompt             = no
distinguished_name = req_distinguished_name
req_extensions     = v3_req

[req_distinguished_name]
countryName             = US
stateOrProvinceName     = CA
localityName            = Mountain View
organizationalUnitName  = Google LLC
commonName              = AMD Reference PSP Verstage BL FW Certificate

# Google Platform Vendor ID [31:24] = 0x94 other bits [23:0] are reserved
serialNumber            = 94000000

[v3_req]
basicConstraints     = CA:FALSE
keyUsage             = nonRepudiation, digitalSignature, keyEncipherment
subjectKeyIdentifier = hash
EOF

  local cmd=(
    openssl req -new
    -config "${config}"
    -key "${key}"
    -out "${csr}"
  )
  echo "> ${cmd[@]}"
  "${cmd[@]}" || die "generating CSR failed"

  echo
  echo "The following hash should be communicated to AMD separately from the CSR"
  echo "to allow it to be verified."
  local digest="${dir}/${KEYNAME}.digest"
  openssl dgst -sha256 "${csr}" >"${digest}" || die "generating digest failed"
  cat "${digest}"
}

main() {
  set -e

  # Check arguments.
  if [[ $# -ne 3 ]]; then
    usage "Error: Incorrect number of arguments"
  fi
  local name=$1
  local dir=$2
  local keysize=$3

  if [[ "${keysize}" -ne 2048 && "${keysize}" -ne 4096 ]]; then
    usage "Error: invalid keysize"
  fi

  if [[ ! -d "${dir}" ]]; then
    mkdir -p "${dir}"
  else
    echo "Error: ${dir} already exists" >&2
    exit 1
  fi

  local key="${dir}/${KEYNAME}.pem"
  create_psp_key "${name}" "${key}" "${keysize}"
  create_psp_csr "${dir}" "${key}" "${keysize}"
}

main "$@"
