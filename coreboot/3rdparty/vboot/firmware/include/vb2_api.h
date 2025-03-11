/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * APIs between calling firmware and vboot_reference
 *
 * DO NOT INCLUDE THE HEADERS BELOW DIRECTLY!  ONLY INCLUDE THIS FILE!
 *
 * Using vb2_api.h as the single point of contact between calling firmware and
 * vboot allows subsequent refactoring of vboot (renaming of headers, etc.)
 * without churning other projects' source code.
 */

#ifndef VBOOT_REFERENCE_VB2_API_H_
#define VBOOT_REFERENCE_VB2_API_H_

/* Standard APIs */
#include "../2lib/include/2api.h"

#endif  /* VBOOT_REFERENCE_VB2_API_H_ */
