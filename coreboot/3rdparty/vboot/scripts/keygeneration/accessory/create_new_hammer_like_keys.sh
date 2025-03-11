#!/bin/bash

# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Load common constants and functions.
export HAS_ARG_KEYNAME=1
# shellcheck source=common_leverage_hammer.sh
. "$(dirname "$0")/common_leverage_hammer.sh"

main() {
  set -e

  leverage_hammer_to_create_key "$@"
}

main "$@"
