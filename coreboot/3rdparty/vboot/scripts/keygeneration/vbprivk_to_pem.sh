#!/bin/bash
# Copyright 2024 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Generates PEM encoded private key from a .vbprivk

# Load common constants and functions.
# shellcheck source=common.sh
# shellcheck disable=SC1091
. "$(dirname "$0")/common.sh"

set -eu -o pipefail

usage() {
	cat <<EOF
Usage: $0 [options]

Options:
	--input <file>          vbprivk private key (default: stdin)
	--output <file>         PEM encoded private key (default: stdout)
EOF

	if [[ $# -ne 0 ]]; then
		die "unknown option $*"
	else
		exit 0
	fi
}

# Reads a signed 64 bit integer from stdin
readi64() {
	local output
	output="$(od --address-radix=none --read-bytes=8 --format=d8)"
	# Drop leading padding and zeros
	echo "$(("${output}"))"
}

main() {
	local input_fd=0 # stdin
	local output_fd=1 # stdout
	while [[ $# -gt 0 ]]; do
		case $1 in
		--input)
			if ! exec 3< "$2"; then
				die "Failed to open input file '$2'"
			fi
			input_fd=3
			shift
			;;
		--output)
			if ! exec 4> "$2"; then
				die "Failed to open output file '$2'"
			fi
			output_fd=4
			shift
			;;
		-h|--help)
			usage
			;;
		*)
			usage "$1"
			;;
		esac
		shift
	done

	# A `vbprivk` is comprised of an 8 byte header followed by a DER encoded
	# PKCS#1 RSA Private Key. We read the 8 byte header from the input_fd
	# (which increments file position) and verify that it's a sane value.
	#
	# See /vboot_reference/firmware/2lib/include/2crypto.h
	local vb2_crypto_algorithm
	vb2_crypto_algorithm="$(readi64 <&"${input_fd}")"

	if [[ "${vb2_crypto_algorithm}" -lt 0 || \
			"${vb2_crypto_algorithm}" -gt 17 ]]; then
		die "Unknown vbprivk format"
	fi

	# Convert the remainder of the input_fd to base64.
	echo -n "-----BEGIN RSA PRIVATE KEY-----
$(base64 --wrap=64 <&"${input_fd}")
-----END RSA PRIVATE KEY-----
" >&"${output_fd}"
}
main "$@"
