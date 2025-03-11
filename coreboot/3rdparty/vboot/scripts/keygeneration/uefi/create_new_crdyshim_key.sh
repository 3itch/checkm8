#!/bin/bash

# Copyright 2024 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Load common constants and functions.
# shellcheck source=../common.sh
. "$(dirname "$0")/../common.sh"


if [ $# -ne 1 ]; then
  cat <<EOF
Usage: $0 <out_dir>

Output: <out_dir>/crdyshim.priv.pem and <out_dir>/crdyshim.pub.pem
EOF
  exit 1
fi

out_dir=$1
generate_ed25519_key "${out_dir}/crdyshim"
