#!/bin/bash

# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Load common constants and functions.
# shellcheck source=../common.sh
. "$(dirname "$0")/../common.sh"

usage() {
  cat <<EOF
Usage: ${PROG} [options] <key_file_base_name>

Options:
  -o, --output_dir <dir>:    Where to write the keys (default is cwd)
EOF

  if [[ $# -ne 0 ]]; then
    die "$*"
  else
    exit 0
  fi
}

generate_rsa3070_key() {
  local base_name="$1"
  local len="3070"

  echo "creating ${base_name} key pair..."

  # Make the RSA key pair.
  openssl genrsa -F4 -out "${base_name}.pem" "${len}"
  openssl rsa -in "${base_name}.pem" -outform PEM \
    -pubout -out "${base_name}.pem.pub"
}

main() {
  set -euo pipefail

  local base_name
  local output_dir="${PWD}"

  base_name=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
    -h|--help)
      usage
      ;;
    -o|--output_dir)
      output_dir="$2"
      if [[ ! -d "${output_dir}" ]]; then
        die "output dir (${output_dir}) doesn't exist."
      fi
      shift
      ;;
    -*)
      usage "Unknown option: $1"
      ;;
    *)
      if [[ -z ${base_name} ]]; then
        base_name="$1"
      else
        usage "Unknown argument $1"
      fi
      ;;
    esac
    shift
  done

  if [[ -z ${base_name} ]]; then
    usage "Key file base name missing"
  fi

  generate_rsa3070_key "${output_dir}/${base_name}"
}

main "$@"
