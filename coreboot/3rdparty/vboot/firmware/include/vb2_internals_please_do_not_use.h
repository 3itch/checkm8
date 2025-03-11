/* Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Allows the caller to peek into vboot2 data structures, by including a
 * specific set of internal header files.  Including this header means the
 * caller is broken and should be fixed.
 *
 * TODO(chromium:957880): The existence of this header is a bug, and it should
 * be removed when it is no longer used.
 */

#ifndef VBOOT_REFERENCE_VB2_INTERNALS_PLEASE_DO_NOT_USE_H_
#define VBOOT_REFERENCE_VB2_INTERNALS_PLEASE_DO_NOT_USE_H_

/*
 * Coreboot should not need access to vboot2 internals.  But right now it does.
 * At least this forces it to do so through a relatively narrow hole so vboot2
 * refactoring can continue.
 *
 * Please do not rip this into a wider hole, or expect this hole to continue.
 */
#include "../2lib/include/2misc.h"  /* for vb2_get_sd() */
#include "../2lib/include/2struct.h"  /* for vb2_shared_data struct */

#endif  /* VBOOT_REFERENCE_VB2_INTERNALS_PLEASE_DO_NOT_USE_H_ */
