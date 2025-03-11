/* Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef VBOOT_REFERENCE_FLASH_HELPERS_H_
#define VBOOT_REFERENCE_FLASH_HELPERS_H_

#include "futility.h"
#include "updater.h"

/*
 * Prepare for flashrom interaction. Setup cfg from args and put servo into
 * flash mode if servo is in use. If this succeeds teardown_flash must be
 * called.
 */
int setup_flash(struct updater_config **cfg,
		struct updater_config_arguments *args);

/* Cleanup objects created in setup_flash and release servo from flash mode. */
void teardown_flash(struct updater_config *cfg);

#endif /* VBOOT_REFERENCE_FLASH_HELPERS_H_ */
