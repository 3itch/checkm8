#!/bin/bash

# Copyright 2010 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

if [ $# -ne 1 ]; then
  echo "Usage: $0 <private_key_pem_file>"
  echo "Reads data to sign from stdin, encrypted data is output to stdout"
  exit 1
fi

openssl rsautl -sign -inkey "$1"
