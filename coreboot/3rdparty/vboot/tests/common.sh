#!/bin/bash

# Copyright 2010 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Determine script directory.
SCRIPT_DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
ROOT_DIR="$(dirname "${SCRIPT_DIR}")"
SRCDIR="${ROOT_DIR}"
# BUILD_RUN should be supplied from the Makefile.
# Some test scripts change the cwd so use an absolute path.
BUILD_RUN="$(realpath "${BUILD_RUN}")"
BIN_DIR="${BUILD_RUN}/install_for_test/usr/bin"
FUTILITY="${BIN_DIR}/futility"
TEST_DIR="${BUILD_RUN}/tests"
TESTKEY_DIR="${SCRIPT_DIR}/testkeys"
TESTCASE_DIR="${SCRIPT_DIR}/testcases"
TESTKEY_SCRATCH_DIR="${TEST_DIR}/testkeys"

if [ ! -d "${TESTKEY_SCRATCH_DIR}" ]; then
  mkdir -p "${TESTKEY_SCRATCH_DIR}"
fi

# Color output encodings.
COL_RED='\E[31;1m'
COL_GREEN='\E[32;1m'
COL_YELLOW='\E[33;1m'
COL_BLUE='\E[34;1m'
COL_STOP='\E[0;m'

hash_algos=( sha1 sha256 sha512 )
key_lengths=( 1024 2048 4096 8192 2048_exp3 3072_exp3 )

function happy {
  echo -e "${COL_GREEN}$*${COL_STOP}" 1>&2
}

# args: [nested level [message]]
function warning {
  echo -e "${COL_YELLOW}WARNING: $*${COL_STOP}" 1>&2
}

# args: [nested level [message]]
function error {
  local lev=${1:-}
  case "${1:-}" in
    [0-9]*)
      lev=$1
      shift
      ;;
    *) lev=0
      ;;
  esac
  local x
  x=$(caller $lev)
  local cline=${x%% *}
  local cfunc=${x#* }
  cfunc=${cfunc##*/}
  local args="$*"
  local spacer=${args:+: }
  echo -e "${COL_RED}ERROR at ${cfunc}, line ${cline}${spacer}${args}" \
    "${COL_STOP}" 1>&2
  exit 1
}

function check_test_keys {
  [ -d "${TESTKEY_DIR}" ] || \
    error 1 "You must run gen_test_keys.sh to generate test keys first."
}
